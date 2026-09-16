import "pe"
rule SimplePack_13_FinalBuild_81026: PEiD
{
    strings:
        $a = { 4D 5A 90 EB 01 00 52 E9 62 01 00 00 50 45 00 00 4C 01 01 00 00 00 00 }
    condition:
        $a at pe.entry_point

}