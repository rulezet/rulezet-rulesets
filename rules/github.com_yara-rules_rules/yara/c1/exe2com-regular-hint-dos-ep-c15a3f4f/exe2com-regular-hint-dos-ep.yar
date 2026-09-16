import "pe"
rule EXE2COM_regular_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 8C CA 81 C3 ?? ?? 3B 16 ?? ?? 76 ?? BA ?? ?? B4 09 CD 21 CD 20 0D }
    condition:
        $a at pe.entry_point

}