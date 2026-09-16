import "pe"
rule TXT2COM_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? CD 20 }
    condition:
        $a at pe.entry_point

}