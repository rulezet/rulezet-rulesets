import "pe"
rule Obsidium_V1258_V133X_Obsidium_Software_Sign_by_fly: PEiD
{
    strings:
        $a = { EB 01 ?? E8 ?? 00 00 00 EB 02 ?? ?? EB }
    condition:
        $a at pe.entry_point

}