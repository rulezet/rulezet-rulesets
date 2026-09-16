import "pe"
rule APEX_C_BLT_Apex_40_500mhz: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 }
    condition:
        $a at pe.entry_point

}