import "pe"
rule XPack_167_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB }
    condition:
        $a at pe.entry_point

}