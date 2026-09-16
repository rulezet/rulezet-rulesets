import "pe"
rule _PseudoSigner_01_PENightMare_2_Beta_Anorganix_additional: PEiD
{
    strings:
        $a = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9 }
    condition:
        $a at pe.entry_point

}