import "pe"
rule SCRAM_vC5_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? 50 9D 9C 58 25 ?? ?? 75 ?? BA ?? ?? B4 09 CD 21 CD 20 }
    condition:
        $a at pe.entry_point

}