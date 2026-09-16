import "pe"
rule Vx_Number_One: PEiD
{
    strings:
        $a = { F9 07 3C 53 6D 69 6C 65 3E E8 }
    condition:
        $a at pe.entry_point

}