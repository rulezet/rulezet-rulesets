import "pe"
rule PPC_PROTECT_V10_Alexey_Gorchakov: PEiD
{
    strings:
        $a = { FF 5F 2D E9 }
    condition:
        $a at pe.entry_point

}