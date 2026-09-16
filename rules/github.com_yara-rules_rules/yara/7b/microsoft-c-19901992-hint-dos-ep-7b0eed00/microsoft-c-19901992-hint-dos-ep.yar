import "pe"
rule Microsoft_C_19901992_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 }
    condition:
        $a at pe.entry_point

}