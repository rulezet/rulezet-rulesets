import "pe"
rule WATCOM_CCpp_runtime_system_1995: PEiD
{
    strings:
        $a = { 53 56 57 55 8B 00 24 14 8B 00 24 18 8B 6C 24 1C 83 00 03 0F 87 00 01 00 00 89 00 2E FF 24 85 }
    condition:
        $a at pe.entry_point

}