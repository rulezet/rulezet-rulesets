import "pe"
rule Unknown_encryptor_2_PK7Tjrvx: PEiD
{
    strings:
        $a = { 06 B4 52 CD 21 07 E8 ?? ?? B4 62 CD 21 E8 }
    condition:
        $a at pe.entry_point

}