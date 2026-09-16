rule rule_bypass_clm_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bypass-clm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bypass-clm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bypass_clm_offensive_tool_keyword = "\"bypass-clm\"" nocase ascii wide
                        $string2_bypass_clm_offensive_tool_keyword = /\/bypass\-clm\.exe/ nocase ascii wide
                        $string3_bypass_clm_offensive_tool_keyword = /\/bypass\-clm\.git/ nocase ascii wide
                        $string4_bypass_clm_offensive_tool_keyword = /\\bypass\-clm\.exe/ nocase ascii wide
                        $string5_bypass_clm_offensive_tool_keyword = /\\bypass\-clm\.sln/ nocase ascii wide
                        $string6_bypass_clm_offensive_tool_keyword = /\\bypass\-clm\\Program\.cs/ nocase ascii wide
                        $string7_bypass_clm_offensive_tool_keyword = /\\Tasks\\bypass\-clm/ nocase ascii wide
                        $string8_bypass_clm_offensive_tool_keyword = /\\Windows\\Microsoft\.NET\\.{0,1000}\\InstallUtil\.exe\s\/logfile\=\s\/LogToConsole\=false\s\/U\s.{0,1000}\:\\Windows\\Tasks\\/ nocase ascii wide
                        $string9_bypass_clm_offensive_tool_keyword = "0b1a6a5a3e7a22a2f68a7b2b83b33117a63f0d6337dddb3d41b250a995210d79" nocase ascii wide
                        $string10_bypass_clm_offensive_tool_keyword = "C8D738E6-8C30-4715-8AE5-6A8FBFE770A7" nocase ascii wide
                        $string11_bypass_clm_offensive_tool_keyword = "calebstewart/bypass-clm" nocase ascii wide

    condition:
        any of them
}