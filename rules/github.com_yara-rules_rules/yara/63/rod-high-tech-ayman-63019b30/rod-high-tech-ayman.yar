import "pe"
rule ROD_High_TECH_Ayman: PEiD
{
    strings:
        $a = { 60 8B 15 1D 13 40 00 F7 E0 8D 82 83 19 00 00 E8 58 0C 00 00 }
    condition:
        $a at pe.entry_point

}