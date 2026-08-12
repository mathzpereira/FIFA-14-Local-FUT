"""Dependency-free reviewed native signature metadata for FIFA 14 discovery."""
from __future__ import annotations


def _target(name: str, rva: int, signature: str, sig_offset: int = 0) -> dict[str, object]:
    return {
        "name": name,
        "rva": rva,
        "sigOffset": sig_offset,
        "signature": bytes.fromhex(signature),
    }


CA_FUNCTION_RVA = 0x00D99790
CA_FUNCTION_SIGNATURE = bytes.fromhex("55 8b ec 8b 45 0c 8b 4d 08 6a 01 50")
UPDATE_RVA = 0x00D9A0B0
UPDATE_SIGNATURE = bytes.fromhex("55 8b ec 53 56 57 8b 7d 08 83 bf 20")
SCREEN_EVENT_DISPATCHER_RVA = 0x0010ECA0
SCREEN_EVENT_DISPATCHER_SIGNATURE = bytes.fromhex("55 8b ec 81 ec 14 02 00 00 56 57 8d")
NAV_TARGETS = (
    _target("NAV::loadView", 0x006E1A40, "55 8b ec e8 98 17 a5 00 8b 10 8b c8"),
    _target("NAV::unloadView", 0x006E1AA0, "55 8b ec e8 38 17 a5 00 8b 10 8b c8"),
    _target("NAV::sendScreenEvent", 0x006B54A0, "55 8b ec 8b 45 10 85 c0 74 23 80 38"),
    _target("NAV::sendAction", 0x006FDA50, "55 8b ec 51 53 56 57 c7 45 fc ff ff ff ff"),
)

AUTH_RESPONSE_CONSTRUCTOR_RVA = 0x0017E830
AUTH_RESPONSE_PARSER_RVA = 0x0017E910
AUTH_RESPONSE_SCALAR_CALLBACK_RVA = 0x0017E9A0
AUTH_RESPONSE_KEY_MAPPER_RVA = 0x0017EB00

CARDS_TARGETS = (
    _target("PlugInitialize_", 0x00003720, "55 8b ec"),
    _target("PlugDeinitialize_", 0x00003970, "56 e8 da fd ff ff"),
    _target("GetPhishingQuestion launch", 0x00052680, "55 8b ec 83 ec 2c 56 8b f1 8b 4d 08"),
    _target("RetrievePhishingQuestion callback", 0x0004F1B0, "55 8b ec 83 ec 10 53 56 57 8b 7d 08"),
    _target("Phishing-question response allocator", 0x00132C00, "8b 49 04 8b 01 8b 50 08 56 6a 00 68"),
    _target("Phishing-question response parser", 0x00132C50, "55 8b ec 81 ec bc 00 00 00 56 57 6a 00"),
    _target("Phishing-question URL builder", 0x00132EA0, "55 8b ec 81 ec 18 02 00 00 68 ff 01 00 00"),
    _target("Operation 89 descriptor status setter", 0x00130490, "55 8b ec 8a 45 08"),
    _target("ValidatePhishingAnswer launch", 0x00052860, "55 8b ec 83 ec 44 53 56 57 8b f1"),
    _target("ValidatePhishingAnswer callback", 0x0004F2A0, "55 8b ec 8b 45 08 83 78 18 00 56 8b f1"),
    _target("Phishing-validation response allocator", 0x00139A20, "8b 49 04 8b 01 8b 50 08 56 6a 00 68"),
    _target("Phishing-validation response parser", 0x00139A50, "b0 01 c2 04 00"),
    _target("Phishing-validation URL builder", 0x00139BA0, "55 8b ec 81 ec 30 01 00 00 56 68 ff 00 00 00"),
    _target("Operation 91 descriptor status setter", 0x001304B0, "55 8b ec 8a 45 08"),
    _target("GetTrustedConsoleList launch", 0x00052990, "55 8b ec 83 ec 2c 56 8b f1 8b 4d 08"),
    _target("GetTrustedConsoleList dispatch checkpoint", 0x000529FF, "ff d2"),
    _target("RetrieveTrustedConsoleList callback", 0x0004F310, "55 8b ec 83 ec 08 53 8b 5d 08 8b 43 18"),
    _target("Trusted-console response allocator", 0x00132FC0, "8b 49 04 8b 01 8b 50 08 53 56 33 db"),
    _target("Trusted-console status handler", 0x00133000, "55 8b ec 8b 45 08 3d f7 01 00 00"),
    _target("Trusted-console response parser", 0x00133020, "55 8b ec 81 ec bc 00 00 00 56 57 6a"),
    _target("Trusted-console URL builder", 0x00133290, "55 8b ec 81 ec 18 02 00 00 68 ff 00 00 00"),
    _target("Trusted-console formatted suffix checkpoint", 0x001332DC, "8b 55 08 8d 8d e8 fd ff ff"),
    _target("Device ID accessor", 0x0013F210, "00 0f 85 1c 01 00 00 6a 10", 6),
    _target("JSON key mapper", 0x00166A00, "55 8b ec 8b 45 08 6a 00 68 c5 9d 1c 81"),
    _target("GetUserInfo response parser", 0x00132440, "55 8b ec 81 ec b8 00 00 00 56 57 6a 00 8b f1"),
    _target("GetUserInfo user subparser", 0x00143410, "55 8b ec 83 ec 20 56 8b 75 0c 8b ce"),
    _target("FUT login stage handler", 0x00084D50, "55 8b ec 83 ec 0c 53 56 57 33 f6 8b f9"),
    _target("FUT login stage helper A", 0x000848C0, "55 8b ec a1 68 73 1d 10 8b 55 08"),
    _target("FUT login stage helper B", 0x00084910, "55 8b ec 8b 45 08 39 05 60 73 1d 10"),
    _target("FUT login stage helper C", 0x000850F0, "55 8b ec 8b 45 0c 53 56 57 8b f1"),
    _target("FUT_IcebreakerManager BuildSquad wrapper", 0x00048690, "53 56 57 e8 48 d2 0c 00 8b 10 8b c8 8b 42 18"),
    _target("FUT_IcebreakerManager ClearSquad wrapper", 0x00048780, "53 56 57 e8 58 d1 0c 00 8b 10 8b c8 8b 42 18"),
    _target("FUT_IcebreakerManager RetrievePack wrapper", 0x00049690, "55 8b ec 81 ec 3c 04 00 00 53 56 57 6a 00"),
    _target("FUT_IcebreakerManager RetrievePackList wrapper", 0x00049960, "55 8b ec 83 ec 28 53 56 57 6a 00"),
    _target("Icebreaker pack-list path handler", 0x00165D10, "55 8b ec 8b 4d 08 68 20 f9 1a 10 68 f8 f8 1a 10"),
    _target("Icebreaker pack-entry parser", 0x00165D30, "55 8b ec 83 ec 1c 56 8b 75 0c 8b ce c7 45 fc 66"),
    _target("Icebreaker pack-list response parser", 0x00166360, "55 8b ec 81 ec 9c 02 00 00 56 6a 00 6a 00"),
    _target("Operation 92 descriptor status setter", 0x001304C0, "55 8b ec 8a 45 08"),
    _target("Authentication WebService constructor", 0x00131620, "8b c1 33 c9 c7 00 b8 72 1a 10"),
    _target("Authentication WebService initialize", 0x001316E0, "55 8b ec 83 ec 0c 56 57 8b f1"),
    _target("Authentication request start", 0x0015F490, "55 8b ec 81 ec e8 03 00 00 53 56 6a 00"),
    _target("Authentication JSON builder", 0x0015EF70, "55 8b ec 81 ec 6c 02 00 00 53 56 57"),
    _target("Authentication EASW-Session null check", 0x0015F2B4, "85 f6 0f 84 62 01 00 00"),
    _target("Authentication EASW-Token null check", 0x0015F2FA, "85 f6 0f 84 b3 00 00 00"),
    _target("Authentication request submit", 0x0015EE20, "55 8b ec 81 ec 30 0b 00 00 53 56 57 6a 17"),
    _target("Authentication SID accessor", 0x0015EE10, "8b 81 ac 01 00 00 c3"),
    _target("Authentication response constructor", AUTH_RESPONSE_CONSTRUCTOR_RVA, "56 68 66 65 64 6d"),
    _target("Authentication response parser", AUTH_RESPONSE_PARSER_RVA, "55 8b ec 81 ec 00 04 00 00 56"),
    _target("Authentication response scalar callback", AUTH_RESPONSE_SCALAR_CALLBACK_RVA, "55 8b ec 8b 89 08 01 00 00"),
    _target("Authentication response key mapper", AUTH_RESPONSE_KEY_MAPPER_RVA, "55 8b ec 56 8b 75 08 b9 70 2c 1b 10"),
    _target("Operation 23 descriptor status setter", 0x00130070, "55 8b ec 8a 45 08 a2 e9 32 1d 10"),
    _target("FUT static-asset state setter", 0x0015BA80, "55 8b ec 8b 45 08 89 41 38"),
    _target("FUT static-asset state getter", 0x0015BA90, "8b 41 38 c3"),
    _target("FUT locstrings response parser", 0x0015BC40, "55 8b ec 81 ec 14 01 00 00 56 6a 00 6a 00"),
    _target("FUT locstrings path builder", 0x0015BD20, "55 8b ec 83 ec 58 56 8b f1"),
    _target("FUT static-asset completion dispatcher", 0x0016C270, "55 8b ec 8b 55 0c 56 8b f1 8b 4d 10"),
)

FIFA14_TARGETS = (
    {"name": "CA_FUNCTION", "rva": CA_FUNCTION_RVA, "signature": CA_FUNCTION_SIGNATURE},
    {"name": "UPDATE", "rva": UPDATE_RVA, "signature": UPDATE_SIGNATURE},
    {
        "name": "SCREEN_EVENT_DISPATCHER",
        "rva": SCREEN_EVENT_DISPATCHER_RVA,
        "signature": SCREEN_EVENT_DISPATCHER_SIGNATURE,
    },
) + NAV_TARGETS


__all__ = [
    "CA_FUNCTION_RVA",
    "CA_FUNCTION_SIGNATURE",
    "CARDS_TARGETS",
    "FIFA14_TARGETS",
    "NAV_TARGETS",
    "SCREEN_EVENT_DISPATCHER_RVA",
    "SCREEN_EVENT_DISPATCHER_SIGNATURE",
    "UPDATE_RVA",
    "UPDATE_SIGNATURE",
]
