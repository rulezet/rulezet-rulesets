import "pe"
rule Private_exe_Protector_V314_SetiSoft_Team_Mato_20100705: PEiD
{
    strings:
        $a = { 50 00 72 00 69 00 76 00 61 00 74 00 65 00 20 00 65 00 78 00 65 00 20 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 6F 00 72 00 00 00 34 00 08 00 01 00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 33 00 2E 00 31 00 2E 00 34 00 2E 00 30 }
    condition:
        $a at pe.entry_point

}