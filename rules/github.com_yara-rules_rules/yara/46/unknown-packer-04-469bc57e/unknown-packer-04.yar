import "pe"
rule Unknown_packer_04: PEiD
{
    strings:
        $a = { BC ?? ?? C3 2E FF 2E ?? ?? CF }
    condition:
        $a at pe.entry_point

}