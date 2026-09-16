import "pe"
rule XPack_167_com_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 53 00 FF FD FF FB FF F9 FF BC 03 00 8B E5 4C 4C C3 }
    condition:
        $a at pe.entry_point

}