import "pe"
rule Windows_Animation_format_additional: PEiD
{
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 41 43 4F 4E 4C 49 53 54 }
    condition:
        $a at pe.entry_point

}