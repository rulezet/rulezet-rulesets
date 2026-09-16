rule rule_unicorn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'unicorn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unicorn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_unicorn_offensive_tool_keyword = /\sunicorn\.py/ nocase ascii wide
                        $string2_unicorn_offensive_tool_keyword = /\.py\s.{0,1000}\.cs\scs\sms/ nocase ascii wide
                        $string3_unicorn_offensive_tool_keyword = /\.txt\sshellcode\shta/ nocase ascii wide
                        $string4_unicorn_offensive_tool_keyword = /\.txt\sshellcode\smacro/ nocase ascii wide
                        $string5_unicorn_offensive_tool_keyword = /\.txt\sshellcode\sms/ nocase ascii wide
                        $string6_unicorn_offensive_tool_keyword = /\/unicorn\.git/ nocase ascii wide
                        $string7_unicorn_offensive_tool_keyword = /\/unicorn\.py/ nocase ascii wide
                        $string8_unicorn_offensive_tool_keyword = /ASBBypass\.ps1/ nocase ascii wide
                        $string9_unicorn_offensive_tool_keyword = "trustedsec/unicorn" nocase ascii wide
                        $string10_unicorn_offensive_tool_keyword = /unicorn\.py\s/ nocase ascii wide
                        $string11_unicorn_offensive_tool_keyword = /unicorn\-master\.zip/ nocase ascii wide

    condition:
        any of them
}