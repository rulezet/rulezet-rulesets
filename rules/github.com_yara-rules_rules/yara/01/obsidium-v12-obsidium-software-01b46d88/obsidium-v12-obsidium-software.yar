import "pe"
rule Obsidium_V12_Obsidium_Software: PEiD
{
    strings:
        $a = { EB 02 ?? ?? E8 77 1E 00 00 }
    condition:
        $a at pe.entry_point

}