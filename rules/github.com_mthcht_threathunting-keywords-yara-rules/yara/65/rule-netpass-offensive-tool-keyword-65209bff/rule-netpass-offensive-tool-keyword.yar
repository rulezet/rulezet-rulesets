rule rule_netpass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'netpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netpass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_netpass_offensive_tool_keyword = /\/utils\/network_password_recovery\.html/ nocase ascii wide
                        $string2_netpass_offensive_tool_keyword = "17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180" nocase ascii wide
                        $string3_netpass_offensive_tool_keyword = "17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180" nocase ascii wide
                        $string4_netpass_offensive_tool_keyword = "60724a25dd319ec57b77e16c52e52a09c7b82ed4ea38dab6d6c2e880dcebb439" nocase ascii wide
                        $string5_netpass_offensive_tool_keyword = /f\:\\temp\\pass\.html/ nocase ascii wide
                        $string6_netpass_offensive_tool_keyword = /netpass\.exe/ nocase ascii wide
                        $string7_netpass_offensive_tool_keyword = /netpass\.zip/ nocase ascii wide
                        $string8_netpass_offensive_tool_keyword = /netpass_x64\.exe/ nocase ascii wide
                        $string9_netpass_offensive_tool_keyword = /netpass\-x64\.zip/ nocase ascii wide
                        $string10_netpass_offensive_tool_keyword = "Network Password Recovery v" nocase ascii wide

    condition:
        any of them
}