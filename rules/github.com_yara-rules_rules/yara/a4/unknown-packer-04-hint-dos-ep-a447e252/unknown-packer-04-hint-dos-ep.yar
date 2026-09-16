import "pe"
rule Unknown_packer_04_Hint_DOS_EP: PEiD
{
    strings:
        $a = { BC ?? ?? C3 2E FF 2E ?? ?? CF }
    condition:
        $a at pe.entry_point

}