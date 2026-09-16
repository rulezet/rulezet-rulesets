import "pe"
rule REC_C0ded_by_ROSE_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 06 1E 0E 0E 07 1F B4 30 CD 21 86 E0 3D 00 03 73 ?? CD 20 EB }
    condition:
        $a at pe.entry_point

}