import "pe"
rule Unknown_packer_02: PEiD
{
    strings:
        $a = { FA 8C DE 8C CF 8E DF 8E C7 83 C7 ?? BB }
    condition:
        $a at pe.entry_point

}