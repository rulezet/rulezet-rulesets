import "pe"
rule DOS32_v33_DOS_Extender_and_Loader_additional: PEiD
{
    strings:
        $a = { 0E 1F FC 9C 5B 8B C3 80 F4 ?? 50 9D 9C 58 3A E7 75 ?? BA ?? ?? B4 09 CD 21 B4 4C CD 21 }
    condition:
        $a at pe.entry_point

}