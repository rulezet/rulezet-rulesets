import "pe"
rule TXT2COM_v206_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 8D 26 ?? ?? E8 ?? ?? B8 ?? ?? CD 21 CD 20 54 58 54 32 43 4F 4D 20 }
    condition:
        $a at pe.entry_point

}