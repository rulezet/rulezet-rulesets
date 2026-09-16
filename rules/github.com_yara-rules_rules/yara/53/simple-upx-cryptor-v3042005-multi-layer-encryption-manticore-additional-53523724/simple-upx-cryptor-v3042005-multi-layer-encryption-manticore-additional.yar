import "pe"
rule Simple_UPX_Cryptor_v3042005_multi_layer_encryption_MANtiCORE_additional: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }
    condition:
        $a at pe.entry_point

}