import "pe"
rule PE_SHiELD_02_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }
    condition:
        $a at pe.entry_point

}