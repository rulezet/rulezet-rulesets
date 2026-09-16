import "pe"
rule A3E_TXT2COM_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 1E 33 C0 50 BE ?? ?? 81 C6 ?? ?? B8 ?? ?? 8E C0 BF ?? ?? B9 ?? ?? F3 A5 CB }
    condition:
        $a at pe.entry_point

}