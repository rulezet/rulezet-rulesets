import "pe"
rule PPC_PROTECT_V11X_Alexey_Gorchakov: PEiD
{
    strings:
        $a = { FF 5F 2D E9 20 00 9F E5 00 00 90 E5 18 00 8F E5 18 00 9F E5 00 00 90 E5 10 00 8F E5 01 00 A0 E3 00 00 00 EB 02 00 00 EA 04 F0 1F E5 }
    condition:
        $a at pe.entry_point

}