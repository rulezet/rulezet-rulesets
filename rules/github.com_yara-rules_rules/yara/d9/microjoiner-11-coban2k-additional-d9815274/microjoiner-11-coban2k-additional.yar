import "pe"
rule MicroJoiner_11_coban2k_additional: PEiD
{
    strings:
        $a = { BE 0C 70 40 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }
    condition:
        $a at pe.entry_point

}