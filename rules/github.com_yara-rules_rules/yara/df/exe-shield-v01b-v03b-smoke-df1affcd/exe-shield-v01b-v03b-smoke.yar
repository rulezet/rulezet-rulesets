import "pe"
rule EXE_Shield_V01b_V03b_SMoKE: PEiD
{
    strings:
        $a = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 }
    condition:
        $a at pe.entry_point

}