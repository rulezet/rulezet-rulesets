import "pe"
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Borland_Cpp_: PEiD
{
    strings:
        $a = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }
    condition:
        $a at pe.entry_point

}