rule apt_win_3cx_backdoored_lib: UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-03-30"
        description = "Detects the malicious library delivered in the backdoored 3CX installer."
        hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
        reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $shellcode =  {
                        44 8D 4A ??
                        44 8D 92 ?? ?? ?? ??
                        45 85 C9
                        45 0F 49 D1
                        41 81 E2 00 FF FF FF
                        41 F7 DA
                        44 01 D2
                        FF C2
                        4C 63 CA
                        46 8A 94 0C ?? ?? ?? ??
                        45 00 D0
                        45 0F B6 D8
                        42 8A AC 1C ?? ?? ?? ??
                        46 88 94 1C ?? ?? ?? ??
                        42 88 AC 0C ?? ?? ?? ??
                        42 02 AC 1C ?? ?? ?? ??
                        44 0F B6 CD
                        46 8A 8C 0C ?? ?? ?? ??
                        45 30 0C 0E
                        48 FF C1
                        48 39 C8
                        75 ??
                }

    condition:
        all of them
}