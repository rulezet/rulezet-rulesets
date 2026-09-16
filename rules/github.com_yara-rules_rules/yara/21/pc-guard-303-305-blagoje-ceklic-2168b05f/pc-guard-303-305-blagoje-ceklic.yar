import "pe"
rule PC_Guard_303_305_Blagoje_Ceklic: PEiD
{
    strings:
        $a = { 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 }
    condition:
        $a at pe.entry_point

}