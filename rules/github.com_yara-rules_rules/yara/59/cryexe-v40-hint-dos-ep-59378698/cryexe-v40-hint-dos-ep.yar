import "pe"
rule CryExe_v40_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? E9 ?? ?? 31 ED EB ?? F5 }
    condition:
        $a at pe.entry_point

}