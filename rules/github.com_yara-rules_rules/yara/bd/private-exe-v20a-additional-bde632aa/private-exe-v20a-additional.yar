import "pe"
rule Private_EXE_v20a_additional: PEiD
{
    strings:
        $a = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D }
    condition:
        $a at pe.entry_point

}