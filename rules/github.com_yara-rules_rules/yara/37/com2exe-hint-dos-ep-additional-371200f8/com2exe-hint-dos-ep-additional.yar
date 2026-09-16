import "pe"
rule COM2EXE_Hint_DOS_EP_additional: PEiD
{
    strings:
        $a = { EB ?? 5B 0E 1F 81 }
    condition:
        $a at pe.entry_point

}