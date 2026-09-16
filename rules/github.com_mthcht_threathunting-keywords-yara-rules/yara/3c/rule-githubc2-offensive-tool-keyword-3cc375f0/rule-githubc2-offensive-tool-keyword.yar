rule rule_GithubC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GithubC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GithubC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GithubC2_offensive_tool_keyword = /\/GithubC2\.git/ nocase ascii wide
                        $string2_GithubC2_offensive_tool_keyword = /\\Implant\.exe\s/ nocase ascii wide
                        $string3_GithubC2_offensive_tool_keyword = "29446C11-A1A5-47F6-B418-0D699C6C3339" nocase ascii wide
                        $string4_GithubC2_offensive_tool_keyword = /AbuseGithubAPI.{0,1000}\.cpp/ nocase ascii wide
                        $string5_GithubC2_offensive_tool_keyword = /AbuseGithubAPI.{0,1000}\.exe/ nocase ascii wide
                        $string6_GithubC2_offensive_tool_keyword = "F3C62326-E221-4481-AC57-EF7F76AAF27B" nocase ascii wide
                        $string7_GithubC2_offensive_tool_keyword = "GithubC2-main" nocase ascii wide
                        $string8_GithubC2_offensive_tool_keyword = /TeamServer\.exe\s.{0,1000}github\.com/ nocase ascii wide
                        $string9_GithubC2_offensive_tool_keyword = "TheD1rkMtr/GithubC2" nocase ascii wide

    condition:
        any of them
}