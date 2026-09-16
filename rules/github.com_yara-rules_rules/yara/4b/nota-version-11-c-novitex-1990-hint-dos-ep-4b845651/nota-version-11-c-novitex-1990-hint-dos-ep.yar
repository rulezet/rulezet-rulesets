import "pe"
rule NOTA_Version_11_c_Novitex_1990_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? 06 1E 33 C0 8E D8 BE ?? ?? 0E 07 BF ?? ?? B9 ?? ?? FC F3 A4 1F 8C D3 BE ?? ?? 8B D4 8E D6 BC ?? ?? 8B F4 }
    condition:
        $a at pe.entry_point

}