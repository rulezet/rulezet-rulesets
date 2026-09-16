import "pe"
rule Armadillo_v1xx_v2xx: PEiD
{
    strings:
        $a = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 }
    condition:
        $a at pe.entry_point

}