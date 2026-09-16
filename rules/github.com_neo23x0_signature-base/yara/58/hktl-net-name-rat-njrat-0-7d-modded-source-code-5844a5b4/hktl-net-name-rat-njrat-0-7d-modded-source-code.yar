rule HKTL_NET_NAME_RAT_NjRat_0_7d_modded_source_code {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/AliBawazeEer/RAT-NjRat-0.7d-modded-source-code"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "2b7d1f75-0164-561e-8199-32c601cbca98"
    strings:
        $name = "RAT-NjRat-0.7d-modded-source-code" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}