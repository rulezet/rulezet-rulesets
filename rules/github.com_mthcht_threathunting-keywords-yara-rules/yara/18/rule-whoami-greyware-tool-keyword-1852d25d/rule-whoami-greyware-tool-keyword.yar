rule rule_whoami_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'whoami' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whoami"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_whoami_greyware_tool_keyword = " -exec bypass -nop -c whoami" nocase ascii wide
                        $string2_whoami_greyware_tool_keyword = "whoami /all" nocase ascii wide
                        $string3_whoami_greyware_tool_keyword = "whoami /domain" nocase ascii wide
                        $string4_whoami_greyware_tool_keyword = "whoami /groups" nocase ascii wide
                        $string5_whoami_greyware_tool_keyword = "whoami /priv" nocase ascii wide
                        $string6_whoami_greyware_tool_keyword = "whoami" nocase ascii wide
                        $string7_whoami_greyware_tool_keyword = /whoami\.exe.{0,1000}\s\/groups/ nocase ascii wide

    condition:
        any of them
}