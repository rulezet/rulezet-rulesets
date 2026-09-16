import "pe"
rule FreeCryptor_03_GlOFF: PEiD
{
    strings:
        $a = { 1E 98 3? }
    condition:
        $a at pe.entry_point

}