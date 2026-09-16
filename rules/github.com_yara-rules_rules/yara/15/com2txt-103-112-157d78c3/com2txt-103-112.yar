import "pe"
rule COM2TXT_103_112: PEiD
{
    strings:
        $a = { 54 5F 4F 4F 57 57 33 3D 58 58 57 58 35 20 32 50 59 35 77 33 50 5F 2D 6C 2E 50 2D 4B 44 31 45 70 2D 4F 4C 50 5A 2D 70 4A 50 2D 70 77 34 30 50 51 58 35 66 73 50 75 0D 0A 00 00 00 00 00 00 00 00 00 00 00 00 35 46 65 2C 78 50 51 58 2D 3D 2E 50 }
    condition:
        $a at pe.entry_point

}