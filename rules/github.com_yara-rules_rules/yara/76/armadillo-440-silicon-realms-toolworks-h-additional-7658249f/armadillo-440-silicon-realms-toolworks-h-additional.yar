import "pe"
rule Armadillo_440_Silicon_Realms_Toolworks_h_additional: PEiD
{
    strings:
        $a = { 30 31 2E 30 31 00 00 04 }
    condition:
        $a at pe.entry_point

}