import "pe"
rule PseudoSigner_01_Video_Lan_Client_Anorganix: PEiD
{
    strings:
        $a = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }
    condition:
        $a at pe.entry_point

}