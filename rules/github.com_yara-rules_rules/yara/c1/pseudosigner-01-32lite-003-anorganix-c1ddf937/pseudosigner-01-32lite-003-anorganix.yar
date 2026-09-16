import "pe"
rule PseudoSigner_01_32Lite_003_Anorganix: PEiD
{
    strings:
        $a = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 ?? ?? ?? ?? E9 }
    condition:
        $a at pe.entry_point

}