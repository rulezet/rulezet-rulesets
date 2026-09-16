import "pe"
rule PseudoSigner_02_BJFNT_12_Anorganix: PEiD
{
    strings:
        $a = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00 }
    condition:
        $a at pe.entry_point

}