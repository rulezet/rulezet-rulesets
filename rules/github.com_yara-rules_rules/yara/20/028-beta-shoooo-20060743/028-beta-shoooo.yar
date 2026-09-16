import "pe"
rule _028_beta_shoooo: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B }
    condition:
        $a at pe.entry_point

}