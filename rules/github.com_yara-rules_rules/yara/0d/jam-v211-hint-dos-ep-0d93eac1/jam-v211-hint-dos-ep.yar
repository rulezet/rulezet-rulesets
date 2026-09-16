import "pe"
rule JAM_v211_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 50 06 16 07 BE ?? ?? 8B FE B9 ?? ?? FD FA F3 2E A5 FB 06 BD ?? ?? 55 CB }
    condition:
        $a at pe.entry_point

}