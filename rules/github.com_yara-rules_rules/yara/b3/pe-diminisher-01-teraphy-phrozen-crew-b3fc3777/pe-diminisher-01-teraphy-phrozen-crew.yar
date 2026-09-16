import "pe"
rule PE_Diminisher_01_Teraphy_Phrozen_Crew: PEiD
{
    strings:
        $a = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 }
    condition:
        $a at pe.entry_point

}