import "pe"
rule aPack_058_082_1_EXE: PEiD
{
    strings:
        $a = { 1E 06 8C C8 8E D8 05 00 00 8E C0 50 BE 00 00 33 FF FC B6 01 BD }
    condition:
        $a at pe.entry_point

}