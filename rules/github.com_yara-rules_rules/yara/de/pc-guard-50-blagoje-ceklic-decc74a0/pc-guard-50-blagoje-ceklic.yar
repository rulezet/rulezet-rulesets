import "pe"
rule PC_Guard_50_Blagoje_Ceklic: PEiD
{
    strings:
        $a = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 }
    condition:
        $a at pe.entry_point

}