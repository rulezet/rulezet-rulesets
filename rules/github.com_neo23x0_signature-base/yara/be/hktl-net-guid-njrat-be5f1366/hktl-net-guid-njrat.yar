rule HKTL_NET_GUID_njRAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/njRAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-30"
        modified = "2025-08-15"
        id = "2140d69e-fb15-50a2-ba85-b7c8293003fb"
    strings:
        $typelibguid0lo = "5a542c1b-2d36-4c31-b039-26a88d3967da" ascii wide
        $typelibguid1lo = "6b07082a-9256-42c3-999a-665e9de49f33" ascii wide
        $typelibguid2lo = "c0a9a70f-63e8-42ca-965d-73a1bc903e62" ascii wide
        $typelibguid3lo = "70bd11de-7da1-4a89-b459-8daacc930c20" ascii wide
        $typelibguid4lo = "fc790ee5-163a-40f9-a1e2-9863c290ff8b" ascii wide
        $typelibguid5lo = "cb3c28b2-2a4f-4114-941c-ce929fec94d3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}