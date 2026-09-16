rule HKTL_NET_GUID_SharpSecDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/G0ldenGunSec/SharpSecDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "492dfb79-541a-589d-ac69-468e9b2ab9db"
    strings:
        $typelibguid0lo = "e2fdd6cc-9886-456c-9021-ee2c47cf67b7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}