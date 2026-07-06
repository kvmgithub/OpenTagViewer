from enum import Enum
import json
import os
import traceback
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
import base64
import NSKeyedUnArchiver

from findmy import FindMyAccessory
from findmy.reports import (
    RemoteAnisetteProvider,
    AppleAccount,
    LoginState,
    SmsSecondFactorMethod,
    TrustedDeviceSecondFactorMethod
)
from findmy.reports.twofactor import (
    SyncSecondFactorMethod
)


class TwoFactorMethods(Enum):
    UNKNOWN = 0
    TRUSTED_DEVICE = 1
    PHONE = 2


# Per-accessory rolling-key alignment state (findmy >= 0.8), one JSON file per
# beacon. Persisting this between fetches is what keeps key rotation tracking
# working after the app restarts. On Android, chaquopy points HOME at the
# app-private files directory.
STATE_DIR = Path(os.environ.get("HOME", ".")) / "accessory_state"


def _toUnixEpochMs(dt: datetime) -> int:
    """
    Convert datetime to unix epoch (milliseconds)
    """
    if dt is None:
        return None
    return int(dt.timestamp() * 1000)


def foo(arg: str):
    """For testing..."""
    print("Bar!")
    print(f"The arg was: '{arg}'")

    for i in range(10):
        print(f"Hello {i}!")

    print("Done!")

    return {
        "Some": "Dictionary",
        "key": [1, 2, 3],
        "other": False,
        "and": True,
        "nested": {
            "a": "b",
            "c": "d"
        },
        "set": {"a", "b", "c"},
        "floats": 1.123456,
        "null maybe": None
    }


def decodeBeaconNamingRecordCloudKitMetadata(cleanedBase64: str) -> dict:
    """
    Extract some extra information from within the plist file `cloudKitMetadata` node
    (that is followed by a `<data>` element containing base64)

    Note that `cleanedBase64` must not contain line breaks `\\n`, or tabs `\\t`
    or other whitespace characters that get introduced by some plist parsers


    ### More info:

    The most popular java plist parser, the google java [dd-plist](https://mvnrepository.com/artifact/com.googlecode.plist/dd-plist) library,
    [does not currently support the `NSKeyedArchiver` plist format](https://github.com/3breadt/dd-plist/issues/70) (at the time of writing).

    However somebody has managed to create a parser in python: https://github.com/avibrazil/NSKeyedUnArchiver

    So because there's some interesting data to be extracted from this `NSKeyedArchiver`-encoded data,
    we will extract it using python via this nice library and pass the needed data back to Java

    See:
    - https://www.mac4n6.com/blog/2016/1/1/manual-analysis-of-nskeyedarchiver-formatted-plist-files-a-review-of-the-new-os-x-1011-recent-items
    - https://github.com/malmeloo/FindMy.py/issues/31#issuecomment-2628072362
    - https://github.com/3breadt/dd-plist/issues/70

    """
    try:
        data = base64.b64decode(cleanedBase64)
        d_dict = NSKeyedUnArchiver.unserializeNSKeyedArchiver(data)

        # This is actually a pretty large object, but very little of the data seems useful to our app

        RecordCtime: datetime = d_dict.get("RecordCtime", None)
        RecordMtime: datetime = d_dict.get("RecordMtime", None)
        ModifiedByDevice: str = d_dict.get("ModifiedByDevice", None)

        res = {
            "creationTime": _toUnixEpochMs(RecordCtime),
            "modifiedTime": _toUnixEpochMs(RecordMtime),
            "modifiedByDevice": ModifiedByDevice
        }

        print(f"Computed result: {res}")

        return res

    except Exception:
        print(f"Failed to parse due to {traceback.format_exc()}")
        return None


def _convertToJavaDictWrapper(method: SyncSecondFactorMethod):
    return_obj = {
        "obj": method
    }

    print(f"The input is {method} of class {type(method)}")

    if isinstance(method, TrustedDeviceSecondFactorMethod):
        print("Option: Trusted Device 2FA method")

        return_obj["type"] = TwoFactorMethods.TRUSTED_DEVICE.value

    elif isinstance(method, SmsSecondFactorMethod):
        print(f"Option: SMS ({method.phone_number})")

        return_obj["type"] = TwoFactorMethods.PHONE.value
        return_obj["phoneNumber"] = method.phone_number
        return_obj["phoneNumberId"] = method.phone_number_id

    else:
        print(f"Unmapped 2FA method! (type: {type(method)})")

        return_obj["type"] = TwoFactorMethods.UNKNOWN.value

    return return_obj


def loginSync(email: str, password: str, anisetteServerUrl: str) -> dict:
    try:
        anisette = RemoteAnisetteProvider(anisetteServerUrl)
        acc = AppleAccount(anisette)

        state = acc.login(email, password)

        if state == LoginState.REQUIRE_2FA:  # Account requires 2FA
            methods = acc.get_2fa_methods()

            named_methods_list = []  # create a map for use in Java...
            for method in methods:
                named_methods_list.append(
                    _convertToJavaDictWrapper(method)
                )

            # Java needs to show us a nice UI
            # where we can select how we want to auth...
            return {
                "account": acc,
                "loginState": state.value,
                "loginMethods": named_methods_list
            }

        # Any of the other cases. I'm not sure if this can even happen...
        return {
            "account": acc,
            "loginState": state.value,
            "loginMethods": None
        }

    except Exception as e:
        print(f"Failed to log in due to error: {traceback.format_exc()}")
        return {
            "error": str(e)
        }


def exportToString(account: AppleAccount) -> str:
    return json.dumps(account.to_json())


def getAccount(
        serializedAccountData: str, anisetteServerUrl: str) -> AppleAccount:
    try:
        data = json.loads(serializedAccountData)
        if data.get("type") != "account":
            # pre-findmy-0.8 state from an older app version: not restorable,
            # force a clean re-login instead of limping along half-restored
            print("Stored account state has an unsupported (legacy) format")
            return None

        # like AppleAccount.from_json, but with the anisette server currently
        # configured in the app settings instead of the one in the saved state
        anisette = RemoteAnisetteProvider(anisetteServerUrl)
        acc = AppleAccount(anisette, state_info=data)

        print(f"Login State: {acc.login_state}")

        return acc
    except Exception:
        err = traceback.format_exc()
        print(f"Failed to restore account from string: {err}")
        return None


def _loadAccessory(beaconId: str, plistContent: str) -> FindMyAccessory:
    state_file = STATE_DIR / f"{beaconId}.json"
    if state_file.exists():
        try:
            return FindMyAccessory.from_json(state_file)
        except Exception:
            print(f"Discarding unreadable accessory state for {beaconId}: {traceback.format_exc()}")
    return FindMyAccessory.from_plist(BytesIO(plistContent.encode('utf-8')))


def _saveAccessory(beaconId: str, accessory: FindMyAccessory) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    accessory.to_json(STATE_DIR / f"{beaconId}.json")


def _reportToDict(report) -> dict:
    ts = _toUnixEpochMs(report.timestamp)
    return {
        # published_at/description were removed from findmy's LocationReport
        # in 0.8+; the Java side still expects the keys
        "publishedAt": ts,
        "description": "",
        "timestamp": ts,
        "confidence": report.confidence,
        "latitude": report.latitude,
        "longitude": report.longitude,
        "horizontalAccuracy": report.horizontal_accuracy,
        "status": report.status
    }


def _fetchReports(
        account: AppleAccount,
        beaconId: str,
        plistContent: str,
        start: datetime,
        end: datetime) -> list:
    accessory = _loadAccessory(beaconId, plistContent)

    # findmy scans backwards from the accessory's current key alignment and
    # re-aligns it from the reports it finds (see FindMy.py issue #90)
    reports = account.fetch_location_history(accessory)
    print(f"Got {len(reports)} raw reports for {beaconId}")

    # persist the updated alignment so the next fetch resumes from it
    # instead of re-deriving keys from the pairing date (issue #30)
    _saveAccessory(beaconId, accessory)

    items = [
        _reportToDict(r)
        for r in sorted(reports, key=lambda r: r.timestamp)
        if start <= r.timestamp <= end
    ]
    print(f"  -> {len(items)} reports after filtering to requested time range")
    return items


def getLastReports(
        account: AppleAccount,
        idToPList,
        hoursBack: int) -> dict:
    # JAVA typing: see https://chaquo.com/chaquopy/doc/current/python.html
    # especially this: https://chaquo.com/chaquopy/doc/current/python.html#classes
    try:
        res = {}

        num_items = idToPList.size()
        print(f"getLastReports: num_items={num_items}, hoursBack={hoursBack}")

        end = datetime.now(tz=timezone.utc)
        start = end - timedelta(hours=hoursBack)

        for i in range(0, num_items):
            pair = idToPList.get(i)
            beaconId = pair.first
            plistContent = pair.second

            print(f"Fetching report for {beaconId} for the last {hoursBack} hours...")
            res[beaconId] = _fetchReports(account, beaconId, plistContent, start, end)

        return res

    except Exception:
        err = traceback.format_exc()
        print(f"Failed to fetch all reports due to error: {err}")
        return None


def getReports(
        account: AppleAccount,
        idToPList,
        unixStartMs: int,
        unixEndMs: int) -> dict:
    # JAVA typing: see https://chaquo.com/chaquopy/doc/current/python.html
    # especially this: https://chaquo.com/chaquopy/doc/current/python.html#classes
    try:
        res = {}

        num_items = idToPList.size()
        print(f"getReports: num_items={num_items}, range={unixStartMs}-{unixEndMs}")

        start = datetime.fromtimestamp(unixStartMs / 1000, tz=timezone.utc)
        end = datetime.fromtimestamp(unixEndMs / 1000, tz=timezone.utc)

        for i in range(0, num_items):
            pair = idToPList.get(i)
            beaconId = pair.first
            plistContent = pair.second

            print(f"Fetching report for {beaconId} in time range {unixStartMs}-{unixEndMs}...")
            res[beaconId] = _fetchReports(account, beaconId, plistContent, start, end)

        return res

    except Exception:
        err = traceback.format_exc()
        print(f"Failed to fetch all reports due to error: {err}")
        return None
