rule HKTL_NET_GUID_SyscallPOC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SolomonSklash/SyscallPOC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "1ed5e226-0dcd-5397-b5e8-41f8a14981a1"
    strings:
        $typelibguid0lo = "1e54637b-c887-42a9-af6a-b4bd4e28cda9" ascii wide
        $typelibguid1lo = "198d5599-d9fc-4a74-87f4-5077318232ad" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}