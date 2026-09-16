import "pe"
rule CrackStop_v101_c_Stefan_Esser_1997: PEiD
{
    strings:
        $a = { B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC }
    condition:
        $a at pe.entry_point

}