import "pe"
rule The_Best_Cryptor_FsK: PEiD
{
    strings:
        $a = { EB 06 56 52 55 4C 5A 00 90 90 90 90 90 90 90 90 }
    condition:
        $a at pe.entry_point

}