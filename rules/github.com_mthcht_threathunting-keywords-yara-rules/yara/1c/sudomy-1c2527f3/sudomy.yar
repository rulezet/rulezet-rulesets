rule Sudomy
{
    meta:
        description = "Detection patterns for the tool 'Sudomy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sudomy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/sudomy/
                        $string2 = /\/sudomy\.api/
                        $string3 = /All_SubdomainTOP_Seclist\.txt/
                        $string4 = "-dP -eP -rS -cF -pS -tO -gW --httpx --dnsprobe  -aI webanalyze -sS"
                        $string5 = /processhider\.c/
                        $string6 = "screetsec/Sudomy"
                        $string7 = "screetsec/Vegile"
                        $string8 = /sudomy\.git/
                        $string9 = "sudomy -"

    condition:
        any of them
}