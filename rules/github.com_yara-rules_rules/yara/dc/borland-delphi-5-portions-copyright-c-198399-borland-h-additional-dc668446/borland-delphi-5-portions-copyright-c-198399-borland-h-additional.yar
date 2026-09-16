import "pe"
rule Borland_Delphi_5_Portions_Copyright_c_198399_Borland_h_additional: PEiD
{
    strings:
        $a = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 39 20 42 6F 72 6C 61 6E 64 00 }
    condition:
        $a at pe.entry_point

}