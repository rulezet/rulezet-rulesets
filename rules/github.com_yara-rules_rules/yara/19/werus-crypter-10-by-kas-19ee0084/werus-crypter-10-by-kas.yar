import "pe"
rule Werus_Crypter_10_by_Kas: PEiD
{
    strings:
        $a = { BB E8 12 40 00 80 33 05 E9 7D FF FF FF }
    condition:
        $a at pe.entry_point

}