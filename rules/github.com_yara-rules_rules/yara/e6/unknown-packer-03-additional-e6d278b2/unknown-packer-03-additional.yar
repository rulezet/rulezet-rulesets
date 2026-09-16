import "pe"
rule Unknown_packer_03_additional: PEiD
{
    strings:
        $a = { 06 1E 57 56 50 53 51 52 BD ?? ?? 0E 1F 8C }
    condition:
        $a at pe.entry_point

}