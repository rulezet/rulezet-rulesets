import "pe"
rule TXT2COM: PEiD
{
    strings:
        $a = { E8 ?? ?? CD 20 }
    condition:
        $a at pe.entry_point

}