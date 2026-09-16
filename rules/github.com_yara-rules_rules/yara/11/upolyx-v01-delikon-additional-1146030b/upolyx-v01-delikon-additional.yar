import "pe"
rule UPolyX_V01_Delikon_additional: PEiD
{
    strings:
        $a = { E2 ?? FF ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}