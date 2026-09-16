import "pe"
rule shoooos_Pack_shoooo: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 ?? ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}