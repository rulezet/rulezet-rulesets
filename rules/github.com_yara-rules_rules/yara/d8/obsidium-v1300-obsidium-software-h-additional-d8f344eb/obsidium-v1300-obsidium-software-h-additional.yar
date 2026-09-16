import "pe"
rule Obsidium_v1300_Obsidium_Software_h_additional: PEiD
{
    strings:
        $a = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }
    condition:
        $a at pe.entry_point

}