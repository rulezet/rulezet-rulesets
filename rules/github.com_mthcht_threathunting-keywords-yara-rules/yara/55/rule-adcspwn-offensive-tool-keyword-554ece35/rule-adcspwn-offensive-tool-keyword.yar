rule rule_ADCSPwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADCSPwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSPwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADCSPwn_offensive_tool_keyword = /\.exe\s\-\-adcs\s.{0,1000}\s\-\-remote\s/ nocase ascii wide
                        $string2_ADCSPwn_offensive_tool_keyword = /\/ADCSPwn\.git/ nocase ascii wide
                        $string3_ADCSPwn_offensive_tool_keyword = /\\ADCSPwn/ nocase ascii wide
                        $string4_ADCSPwn_offensive_tool_keyword = ">ADCSPwn<" nocase ascii wide
                        $string5_ADCSPwn_offensive_tool_keyword = "0bb4b892f67fdf903ed5e5df2c85c5ccb71669c298736cf24284412de435509a" nocase ascii wide
                        $string6_ADCSPwn_offensive_tool_keyword = "980EF05F-87D1-4A0A-932A-582FB1BC3AC3" nocase ascii wide
                        $string7_ADCSPwn_offensive_tool_keyword = /ADCSPwn\.csproj/ nocase ascii wide
                        $string8_ADCSPwn_offensive_tool_keyword = /ADCSPwn\.exe/ nocase ascii wide
                        $string9_ADCSPwn_offensive_tool_keyword = /ADCSPwn\.sln/ nocase ascii wide
                        $string10_ADCSPwn_offensive_tool_keyword = /ADCSPwn\.zip/ nocase ascii wide
                        $string11_ADCSPwn_offensive_tool_keyword = "ADCSPwn-master" nocase ascii wide
                        $string12_ADCSPwn_offensive_tool_keyword = "bats3c/ADCSPwn" nocase ascii wide

    condition:
        any of them
}