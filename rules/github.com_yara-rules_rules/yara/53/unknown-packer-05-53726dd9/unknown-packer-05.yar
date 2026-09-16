import "pe"
rule Unknown_packer_05: PEiD
{
    strings:
        $a = { FA BB ?? ?? B9 ?? ?? 87 E5 87 27 03 E3 91 8A CB 80 E1 ?? D3 C4 91 33 E3 87 27 }
    condition:
        $a at pe.entry_point

}