rule SEH_Save : Tactic_DefensiveEvasion Technique_AntiDebugging SubTechnique_SEH
{
    meta:
        author = "Malware Utkonos"
        original_author = "naxonez"
        source = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    strings:
        $a = { 64 ff 35 00 00 00 00 }
    condition:
        WindowsPE and $a
}