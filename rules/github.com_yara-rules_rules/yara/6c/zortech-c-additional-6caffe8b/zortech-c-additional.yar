import "pe"
rule Zortech_C_additional: PEiD
{
    strings:
        $a = { FA FC B8 ?? ?? ?? 8C C8 8E D8 }
    condition:
        $a at pe.entry_point

}