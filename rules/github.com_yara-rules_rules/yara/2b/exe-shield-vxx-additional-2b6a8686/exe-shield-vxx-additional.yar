import "pe"
rule Exe_Shield_vxx_additional: PEiD
{
    strings:
        $a = { 53 E8 00 00 00 00 5B 8B C3 2D }
    condition:
        $a at pe.entry_point

}