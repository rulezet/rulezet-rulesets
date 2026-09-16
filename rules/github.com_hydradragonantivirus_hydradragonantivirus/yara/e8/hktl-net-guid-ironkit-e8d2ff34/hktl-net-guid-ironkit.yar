rule HKTL_NET_GUID_IronKit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nshalabi/IronKit"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        score = 50
        date = "2020-12-13"
    strings:
        $typelibguid0 = "68e40495-c34a-4539-b43e-9e4e6f11a9fb" ascii nocase wide
        $typelibguid1 = "641cd52d-3886-4a74-b590-2a05621502a4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}