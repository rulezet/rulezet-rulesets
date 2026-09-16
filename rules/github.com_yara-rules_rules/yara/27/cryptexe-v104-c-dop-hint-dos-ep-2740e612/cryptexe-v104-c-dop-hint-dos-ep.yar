import "pe"
rule CRYPTEXE_v104_c_DOP_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? 8B DC EB ?? EA ?? ?? ?? ?? 01 EA 83 FC ?? 74 ?? EB }
    condition:
        $a at pe.entry_point

}