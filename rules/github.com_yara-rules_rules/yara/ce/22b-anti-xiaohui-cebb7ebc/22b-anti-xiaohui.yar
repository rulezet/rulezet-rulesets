import "pe"
rule _22b_Anti_xiaohui: PEiD
{
    strings:
        $a = { EB F4 11 55 07 8B EC B8 14 80 0E 03 E8 D1 09 00 0A 57 33 D2 FF 75 18 B9 E8 1F DE 16 81 C0 8D BD EE 7F FB F8 }
    condition:
        $a at pe.entry_point

}