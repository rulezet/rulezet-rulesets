import "pe"
rule COOLcryptor_09_kongfoo: PEiD
{
    strings:
        $a = { E8 03 00 00 00 E9 EB 07 FF 04 24 EB 01 FF C3 E8 03 00 00 00 EB 02 EA C3 EB 08 8D 8D 72 08 }
    condition:
        $a at pe.entry_point

}