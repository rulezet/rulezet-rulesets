import "pe"
rule RCryptor_v16b_v16c_Vaska: PEiD
{
    strings:
        $a = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 }
        $b = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}