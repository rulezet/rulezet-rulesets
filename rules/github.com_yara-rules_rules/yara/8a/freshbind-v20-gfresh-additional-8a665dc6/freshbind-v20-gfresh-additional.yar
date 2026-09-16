import "pe"
rule Freshbind_v20_gFresh_additional: PEiD
{
    strings:
        $a = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 10 30 40 00 68 9A 10 40 }
    condition:
        $a at pe.entry_point

}