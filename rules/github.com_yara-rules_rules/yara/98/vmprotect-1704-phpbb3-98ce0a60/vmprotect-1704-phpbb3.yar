import "pe"
rule VMProtect_1704_phpbb3: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}