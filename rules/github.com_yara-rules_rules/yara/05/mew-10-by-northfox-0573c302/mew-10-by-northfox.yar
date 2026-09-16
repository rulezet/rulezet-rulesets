import "pe"
rule MEW_10_by_Northfox: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }
    condition:
        $a at pe.entry_point

}