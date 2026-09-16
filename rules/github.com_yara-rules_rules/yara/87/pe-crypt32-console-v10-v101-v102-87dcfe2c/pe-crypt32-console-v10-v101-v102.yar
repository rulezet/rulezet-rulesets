import "pe"
rule PE_Crypt32_Console_v10_v101_v102: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }
    condition:
        $a at pe.entry_point

}