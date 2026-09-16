import "pe"
rule Obsidium_vxxxx_additional: PEiD
{
    strings:
        $a = { E8 47 19 }
    condition:
        $a at pe.entry_point

}