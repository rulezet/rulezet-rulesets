import "pe"
rule Exe_Shield_v27_additional: PEiD
{
    strings:
        $a = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85 }
    condition:
        $a at pe.entry_point

}