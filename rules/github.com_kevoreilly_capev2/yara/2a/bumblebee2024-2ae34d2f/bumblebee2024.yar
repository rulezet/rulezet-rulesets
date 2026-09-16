rule BumbleBee2024
{
    meta:
        author = "enzok"
        description = "BumbleBee 2024"
        cape_type = "BumbleBee Payload"
        packed = "a20d56ab2e53b3a599af9904f163bb2e1b2bb7f2c98432519e1fbe87c3867e66"
    strings:
        $rc4key = {48 [6] 48 [6] E8 [4] 4C 89 AD [4] 4C 89 AD [4] 4C 89 B5 [4] 4C 89 AD [4] 44 88 AD [4] 48 8D 15 [4] 44 38 2D [4] 75}
        $botidlgt = {4C 8B C1 B? 4F 00 00 00 48 8D 0D [4] E8 [4] 4C 8B C3 48 8D 0D [4] B? 4F 00 00 00 E8 [4] 4C 8B C3 48 8D 0D [4] B? FF 0F 00 00 E8}
        $botid = {90 48 [6] E8 [4] 4C 89 AD [4] 4C 89 AD [4] 4C 89 B5 [4] 4C 89 AD [4] 44 88 AD [4] 48 8D 15 [4] 44 38 2D [4] 75}
        $port = {4C 89 6D ?? 4C 89 6D ?? 4c 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8D 05 [4] 44 38 2D [4] 75}
        $dga1 = {4C 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8B 1D [4] 48 8D 0D [4] E8 [4] 8B F8}
        $dga2 = {48 8D 0D [4] E8 [4] 8B F0 4C 89 6D ?? 4C 89 6D ?? 4C 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8D 15 [4] 44 38 2D [4] 75}
    condition:
        $rc4key and all of ($botid*) and 2 of ($port, $port, $dga1, $dga2)
}