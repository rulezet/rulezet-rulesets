import "pe"
rule Unknown_packer_07_additional: PEiD
{
    strings:
        $a = { 8C C8 05 ?? ?? 50 B8 ?? ?? 50 B0 ?? 06 8C D2 06 83 }
    condition:
        $a at pe.entry_point

}