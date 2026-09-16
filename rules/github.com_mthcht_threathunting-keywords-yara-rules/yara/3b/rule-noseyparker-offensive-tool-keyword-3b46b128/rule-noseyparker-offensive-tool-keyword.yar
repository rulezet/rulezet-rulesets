rule rule_noseyparker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'noseyparker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "noseyparker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_noseyparker_offensive_tool_keyword = " github repos list --org" nocase ascii wide
                        $string2_noseyparker_offensive_tool_keyword = " github repos list --user " nocase ascii wide
                        $string3_noseyparker_offensive_tool_keyword = " scan --github-org" nocase ascii wide
                        $string4_noseyparker_offensive_tool_keyword = " scan --github-user" nocase ascii wide
                        $string5_noseyparker_offensive_tool_keyword = /\/noseyparker\.git/ nocase ascii wide
                        $string6_noseyparker_offensive_tool_keyword = "noseyparker report --datastore " nocase ascii wide
                        $string7_noseyparker_offensive_tool_keyword = "noseyparker scan --datastore " nocase ascii wide
                        $string8_noseyparker_offensive_tool_keyword = "noseyparker summarize --datastore " nocase ascii wide
                        $string9_noseyparker_offensive_tool_keyword = "noseyparker-cli" nocase ascii wide
                        $string10_noseyparker_offensive_tool_keyword = "noseyparker-main" nocase ascii wide
                        $string11_noseyparker_offensive_tool_keyword = /noseyparker\-v.{0,1000}\-universal\-macos/ nocase ascii wide
                        $string12_noseyparker_offensive_tool_keyword = /noseyparker\-v.{0,1000}\-x86_64\-unknown\-linux\-gnu/
                        $string13_noseyparker_offensive_tool_keyword = "praetorian-inc/noseyparker" nocase ascii wide

    condition:
        any of them
}