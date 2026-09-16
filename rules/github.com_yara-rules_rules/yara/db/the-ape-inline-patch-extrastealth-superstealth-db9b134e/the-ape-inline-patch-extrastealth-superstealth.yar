import "pe"
rule The_aPE_Inline_Patch_ExtraStealth_SuperStealth: PEiD
{
    strings:
        $a = { E8 02 ?? ?? ?? EB 01 C3 3E 8B 44 24 FC 50 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 }
    condition:
        $a at pe.entry_point

}