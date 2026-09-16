import "pe"
rule Simple_UPX_Cryptor_v3042005_multi_layer_encryption_MANtiCORE_: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}