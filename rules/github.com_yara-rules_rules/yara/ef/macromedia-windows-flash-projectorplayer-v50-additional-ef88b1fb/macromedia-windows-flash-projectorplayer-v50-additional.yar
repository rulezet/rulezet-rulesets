import "pe"
rule Macromedia_Windows_Flash_ProjectorPlayer_v50_additional: PEiD
{
    strings:
        $a = { 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }
    condition:
        $a at pe.entry_point

}