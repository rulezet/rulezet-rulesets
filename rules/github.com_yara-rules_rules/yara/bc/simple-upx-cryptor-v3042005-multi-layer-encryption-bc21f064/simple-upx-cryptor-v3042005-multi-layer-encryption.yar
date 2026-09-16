import "pe"
rule Simple_UPX_Cryptor_v3042005_multi_layer_encryption: PEiD
{
    strings:
        $a = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }
        $b = { 60 B8 ?? ?? ?? 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}