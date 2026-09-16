import "pe"
rule Sphinx_C_v_19_Hint_DOS_EP_additional: PEiD
{
    strings:
        $a = { EB ?? 31 C0 8E C0 26 C7 06 ?? ?? ?? ?? 26 8C 0E ?? ?? E9 }
    condition:
        $a at pe.entry_point

}