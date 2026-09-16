import "pe"
rule GameGuard_v20065xx_exe_additional: PEiD
{
    strings:
        $a = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }
    condition:
        $a at pe.entry_point

}