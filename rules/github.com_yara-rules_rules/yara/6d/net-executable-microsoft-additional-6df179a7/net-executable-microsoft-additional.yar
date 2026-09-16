import "pe"
rule NET_executable_Microsoft_additional: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 00 00 00 FF 25 }
    condition:
        $a at pe.entry_point

}