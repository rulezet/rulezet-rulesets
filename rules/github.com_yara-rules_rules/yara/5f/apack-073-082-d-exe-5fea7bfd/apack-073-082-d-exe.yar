import "pe"
rule aPack_073_082_d_EXE: PEiD
{
    strings:
        $a = { 8C C8 8E D8 05 00 00 8E C0 50 BE 00 00 33 FF FC B6 01 BD 00 00 }
    condition:
        $a at pe.entry_point

}