import "pe"
rule PESHiELD_v0251: PEiD
{
    strings:
        $a = { 5D 83 ED 06 EB 02 EA 04 8D }
    condition:
        $a at pe.entry_point

}