import "pe"
rule RCryptor_v16d_Vaska: PEiD
{
    strings:
        $a = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }
        $b = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}