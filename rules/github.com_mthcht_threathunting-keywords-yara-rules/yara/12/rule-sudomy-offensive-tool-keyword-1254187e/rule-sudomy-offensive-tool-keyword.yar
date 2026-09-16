rule rule_Sudomy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Sudomy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sudomy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Sudomy_offensive_tool_keyword = /\.\/sudomy/
                        $string2_Sudomy_offensive_tool_keyword = /\/sudomy\.api/
                        $string3_Sudomy_offensive_tool_keyword = /All_SubdomainTOP_Seclist\.txt/
                        $string4_Sudomy_offensive_tool_keyword = "-dP -eP -rS -cF -pS -tO -gW --httpx --dnsprobe  -aI webanalyze -sS"
                        $string5_Sudomy_offensive_tool_keyword = /processhider\.c/
                        $string6_Sudomy_offensive_tool_keyword = "screetsec/Sudomy"
                        $string7_Sudomy_offensive_tool_keyword = "screetsec/Vegile"
                        $string8_Sudomy_offensive_tool_keyword = /sudomy\.git/
                        $string9_Sudomy_offensive_tool_keyword = "sudomy -"

    condition:
        any of them
}