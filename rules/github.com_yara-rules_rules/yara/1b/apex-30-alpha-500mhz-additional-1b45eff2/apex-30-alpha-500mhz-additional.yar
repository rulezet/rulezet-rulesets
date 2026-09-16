import "pe"
rule Apex_30_alpha_500mhz_additional: PEiD
{
    strings:
        $a = { 5F B9 14 00 00 00 51 BE 00 10 40 00 B9 00 ?? ?? 00 8A 07 30 06 46 E2 FB 47 59 E2 EA 68 ?? ?? ?? 00 C3 }
    condition:
        $a at pe.entry_point

}