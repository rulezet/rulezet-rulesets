import "pe"
rule EXE32Pack_v136_SteelBytes: PEiD
{
    strings:
        $a = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? 00 ?? ?? 00 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D 40 00 }
    condition:
        $a at pe.entry_point

}