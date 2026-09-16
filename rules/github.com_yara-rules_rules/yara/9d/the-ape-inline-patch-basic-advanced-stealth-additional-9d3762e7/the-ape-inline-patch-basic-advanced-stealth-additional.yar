import "pe"
rule The_aPE_Inline_Patch_Basic_Advanced_Stealth_additional: PEiD
{
    strings:
        $a = { B9 ?? ?? ?? 00 E8 ?? ?? 00 00 89 01 68 }
    condition:
        $a at pe.entry_point

}