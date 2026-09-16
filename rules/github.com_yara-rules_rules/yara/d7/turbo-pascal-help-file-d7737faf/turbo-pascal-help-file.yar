import "pe"
rule Turbo_Pascal_Help_File: PEiD
{
    strings:
        $a = { 54 55 52 ?? ?? ?? 50 41 53 ?? ?? ?? ?? 48 45 4C 50 }
    condition:
        $a at pe.entry_point

}