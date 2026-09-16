import "pe"
rule _PseudoSigner_02_PENightMare_2_Beta_Anorganix: PEiD
{
    strings:
        $a = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }
    condition:
        $a at pe.entry_point

}