import "pe"
rule ThemidaWinLicense_V1000_V1800_Oreans_Technologies: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}