import "pe"
rule DIET_v144_v145f_additional: PEiD
{
    strings:
        $a = { F9 9C EB }
    condition:
        $a at pe.entry_point

}