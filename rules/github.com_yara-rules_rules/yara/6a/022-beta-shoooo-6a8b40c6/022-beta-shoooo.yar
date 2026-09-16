import "pe"
rule _022_beta_shoooo: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 }
    condition:
        $a at pe.entry_point

}