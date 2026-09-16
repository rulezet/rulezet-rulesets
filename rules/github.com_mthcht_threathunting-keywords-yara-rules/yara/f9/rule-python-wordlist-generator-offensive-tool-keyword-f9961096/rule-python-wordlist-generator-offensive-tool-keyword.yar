rule rule_Python_Wordlist_Generator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Python-Wordlist-Generator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Python-Wordlist-Generator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Python_Wordlist_Generator_offensive_tool_keyword = /wgen\.py/ nocase ascii wide

    condition:
        any of them
}