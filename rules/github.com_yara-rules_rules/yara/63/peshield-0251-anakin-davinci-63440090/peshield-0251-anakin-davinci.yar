import "pe"
rule PESHiELD_0251_ANAKiN_DaVinci: PEiD
{
    strings:
        $a = { 5D 83 ED 06 EB 02 EA 04 8D }
    condition:
        $a at pe.entry_point

}