import "pe"
rule AdFlt2_additional: PEiD
{
    strings:
        $a = { 68 00 01 9C 0F A0 0F A8 60 FD 6A 00 0F A1 BE ?? ?? AD }
    condition:
        $a at pe.entry_point

}