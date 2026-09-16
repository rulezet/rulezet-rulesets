import "pe"
rule COM2EXE_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? 8C CA 81 C2 ?? ?? 3B 16 ?? ?? 76 ?? BA ?? ?? B4 09 CD 21 CD 20 }
    condition:
        $a at pe.entry_point

}