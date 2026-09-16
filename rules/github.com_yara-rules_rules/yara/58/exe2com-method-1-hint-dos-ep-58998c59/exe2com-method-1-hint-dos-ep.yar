import "pe"
rule EXE2COM_Method_1_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 8C DB BE ?? ?? 8B C6 B1 ?? D3 E8 03 C3 03 ?? ?? A3 ?? ?? 8C C8 05 ?? ?? A3 }
    condition:
        $a at pe.entry_point

}