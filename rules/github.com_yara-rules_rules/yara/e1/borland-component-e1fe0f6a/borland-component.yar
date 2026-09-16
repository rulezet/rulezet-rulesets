import "pe"
rule Borland_Component: PEiD
{
    strings:
        $a = { E9 ?? ?? FE FF 8D 40 00 }
    condition:
        $a at pe.entry_point

}