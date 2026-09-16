rule ADCSPwn
{
    meta:
        description = "Detection patterns for the tool 'ADCSPwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSPwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\-\-adcs\s.{0,1000}\s\-\-remote\s/ nocase ascii wide
                        $string2 = /\/ADCSPwn\.git/ nocase ascii wide
                        $string3 = /\\ADCSPwn/ nocase ascii wide
                        $string4 = ">ADCSPwn<" nocase ascii wide
                        $string5 = "0bb4b892f67fdf903ed5e5df2c85c5ccb71669c298736cf24284412de435509a" nocase ascii wide
                        $string6 = "980EF05F-87D1-4A0A-932A-582FB1BC3AC3" nocase ascii wide
                        $string7 = /ADCSPwn\.csproj/ nocase ascii wide
                        $string8 = /ADCSPwn\.exe/ nocase ascii wide
                        $string9 = /ADCSPwn\.sln/ nocase ascii wide
                        $string10 = /ADCSPwn\.zip/ nocase ascii wide
                        $string11 = "ADCSPwn-master" nocase ascii wide
                        $string12 = "bats3c/ADCSPwn" nocase ascii wide

    condition:
        any of them
}