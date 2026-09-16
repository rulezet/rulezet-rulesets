rule HKTL_NET_GUID_KeystrokeAPI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fabriciorissetto/KeystrokeAPI"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "e715bce8-531b-5e2a-bd02-b2fc4990c499"
    strings:
        $typelibguid0lo = "f6fec17e-e22d-4149-a8a8-9f64c3c905d3" ascii wide
        $typelibguid1lo = "b7aa4e23-39a4-49d5-859a-083c789bfea2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}