import "pe"
rule EXE_v10_additional: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 08 4B 40 00 68 36 3A 40 00 64 A1 }
    condition:
        $a at pe.entry_point

}