rule NitrogenLoaderConfig
{
    meta:
        author = "enzok"
        description = "NitrogenLoader Config Extraction"
        cape_options = "bp0=$decrypt1*+1,bp1=$key*,hc0=1,count=0,action0=string:rcx,action1=string:rdx,typestring=NitrogenLoader Config"
    strings:
        $decrypt1 = {48 63 4? 24 ?? 33 D2 48 [0-3] F7 B4 24 [4] 48 8B C2 48 8B 8C 24 [4] 0F BE 04 01}
        $decrypt2 = {8B ?? 24 [1-4] 33 C8 8B C1 48 63 4C 24 ?? 48 8B 94 24 [4] 88 04 0A}
        $decrypt3 = {8B 8C 24 ?? ?? ?? ?? 2B C8 8B C1 48 63 4C 24 ?? 48 8B 94 24 [4] 88 04 0A}
        $key = {74 ?? E8 [4] 85 C0 75 ?? 4? 8B 0D [3] 00 4? 8D 15 [3] 00 E8}
        $taskman_1 = {E8 [4] B9 61 00 00 00 88 84 24 [4] E8 [4] B9 73 00 00 00 88 84 24 [4] E8 [4] B9 6B 00 00 00 88 84 24 [4] E8 [3] FF}
        $taskman_2 = {B9 4D 00 00 00 88 84 24 [4] E8 [4] B9 61 00 00 00 88 84 24 [4] E8 [4] B9 6E 00 00 00 88 84 24 [4] E8 [3] FF}
        $taskman_3 = {B9 61 00 00 00 88 84 24 [4] E8 [4] B9 67 00 00 00 88 84 24 [4] E8 [4] B9 65 00 00 00 88 84 24 [4] E8 [3] FF}
        $taskman_4 = {B9 72 00 00 00 88 84 24 [4] E8 [4] 31 C9 88 84 24 [4] E8 [3] FF}
        $installers_1 = {B9 49 00 00 00 E8 [4] B9 6E 00 00 00 88 84 24 [4] E8 [4] B9 73 00 00 00 88 84 24 [4] E8 [3] FF}
        $installers_2 = {B9 74 00 00 00 88 84 24 [4] E8 [4] B9 61 00 00 00 88 84 24 [4] E8 [4] B9 6C 00 00 00 88 84 24 [4] E8 [3] FF}
        $installers_3 = {B9 6C 00 00 00 88 84 24 [4] E8 [4] B9 65 00 00 00 88 84 24 [4] E8 [3] FF}
        $installers_4 = {B9 72 00 00 00 88 84 24 [4] E8 [4] B9 73 00 00 00 88 84 24 [4] E8 [3] FF}
        $rc4decrypt_1 = {48 89 ?? 4? 89 ?? E8 [4] 4? 8B ?? 24 [1-4] 4? 89 ?? 4? 89 ?? 4? 89 C1 [0-1] 89 ?? E8 [4] 4? 89}
        $rc4decrypt_2 = {E8 [4] 8B ?? 24 [1-4] 4? 89 ?? 48 89 ?? 4? 89 C1 E8 [3] FF}
    condition:
        any of ($decrypt*) or ($key and (3 of ($taskman_*) or 3 of ($installers*) and 1 of ($rc4decrypt_*)))
}