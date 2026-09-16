import "pe"
rule PEShield_02b2: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 8D 00 31 00 00 00 00 00 00 00 00 8A 00 00 32 00 80 00 00 80 00 00 88 00 00 00 EB 00 75 ED }
    condition:
        $a at pe.entry_point

}