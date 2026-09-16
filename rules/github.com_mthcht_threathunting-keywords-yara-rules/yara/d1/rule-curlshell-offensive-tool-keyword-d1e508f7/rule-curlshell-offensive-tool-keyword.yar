rule rule_curlshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'curlshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "curlshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_curlshell_offensive_tool_keyword = /\scurlshell\.py/
                        $string2_curlshell_offensive_tool_keyword = /\.py\s.{0,1000}0\.0\.0\.0.{0,1000}\-\-serve\-forever/
                        $string3_curlshell_offensive_tool_keyword = /\.py\s.{0,1000}\-\-dependabot\-workaround/
                        $string4_curlshell_offensive_tool_keyword = /\.py\s\-\-certificate\s.{0,1000}\.pem\s\-\-private\-key\s.{0,1000}\.pem\s\-\-listen\-port\s/
                        $string5_curlshell_offensive_tool_keyword = /\.py\s\-\-certificate\sfullchain\.pem\s\-\-private\-key\sprivkey\.pem\s\-\-listen\-port\s/
                        $string6_curlshell_offensive_tool_keyword = /\/curlshell\.git/ nocase ascii wide
                        $string7_curlshell_offensive_tool_keyword = /\/curlshell\.git/ nocase ascii wide
                        $string8_curlshell_offensive_tool_keyword = /\/curlshell\.py/ nocase ascii wide
                        $string9_curlshell_offensive_tool_keyword = /\/curlshell\-main\./ nocase ascii wide
                        $string10_curlshell_offensive_tool_keyword = "/curlshell-main/" nocase ascii wide
                        $string11_curlshell_offensive_tool_keyword = /\\curlshell\.py/ nocase ascii wide
                        $string12_curlshell_offensive_tool_keyword = /\\curlshell\-main/ nocase ascii wide
                        $string13_curlshell_offensive_tool_keyword = /\\curlshell\-main\\/ nocase ascii wide
                        $string14_curlshell_offensive_tool_keyword = "b8285e421d702738eab45670ecae439a7228994e7068b04cb51740e47efbfb41" nocase ascii wide
                        $string15_curlshell_offensive_tool_keyword = "curl https://curlshell"
                        $string16_curlshell_offensive_tool_keyword = /curlshell\.py/
                        $string17_curlshell_offensive_tool_keyword = "https://curlshell:"
                        $string18_curlshell_offensive_tool_keyword = /https\:\/\/curlshell\:.{0,1000}\s\|\sbash/
                        $string19_curlshell_offensive_tool_keyword = "irsl/curlshell"

    condition:
        any of them
}