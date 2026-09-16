rule rule_dcomhijack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dcomhijack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dcomhijack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dcomhijack_offensive_tool_keyword = /\/dcomhijack\.cna/ nocase ascii wide
                        $string2_dcomhijack_offensive_tool_keyword = /\/dcomhijack\.git/ nocase ascii wide
                        $string3_dcomhijack_offensive_tool_keyword = /\/dcomhijack\.git/ nocase ascii wide
                        $string4_dcomhijack_offensive_tool_keyword = /\/dcomhijack\.py/ nocase ascii wide
                        $string5_dcomhijack_offensive_tool_keyword = /\\dcomhijack\.py/ nocase ascii wide
                        $string6_dcomhijack_offensive_tool_keyword = "2fe3e062aad09c372500bdef858a32344d95c7b8036d4cb5f0091a2db17b446f" nocase ascii wide
                        $string7_dcomhijack_offensive_tool_keyword = "9f1186262760c8424674045530bb64d541acbd5a5364e5e56f23cae01243a59e" nocase ascii wide
                        $string8_dcomhijack_offensive_tool_keyword = /dcomhijack\.cna/ nocase ascii wide
                        $string9_dcomhijack_offensive_tool_keyword = /dcomhijack\.py\s\-object\s/ nocase ascii wide
                        $string10_dcomhijack_offensive_tool_keyword = /dcomhijack\.py/ nocase ascii wide
                        $string11_dcomhijack_offensive_tool_keyword = "dcomhijack-main" nocase ascii wide
                        $string12_dcomhijack_offensive_tool_keyword = /upload\-dll\s.{0,1000}\s.{0,1000}\.dll/ nocase ascii wide
                        $string13_dcomhijack_offensive_tool_keyword = "WKL-Sec/dcomhijack" nocase ascii wide
                        $string14_dcomhijack_offensive_tool_keyword = "WKL-Sec/dcomhijack" nocase ascii wide

    condition:
        any of them
}