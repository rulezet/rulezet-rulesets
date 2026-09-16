rule rule_RaRCE_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RaRCE' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RaRCE"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RaRCE_offensive_tool_keyword = " CVE-2023-38831-RaRCE" nocase ascii wide
                        $string2_RaRCE_offensive_tool_keyword = /\srarce\.py/ nocase ascii wide
                        $string3_RaRCE_offensive_tool_keyword = "/CVE-2023-38831-RaRCE" nocase ascii wide
                        $string4_RaRCE_offensive_tool_keyword = /\/rarce\.py/ nocase ascii wide
                        $string5_RaRCE_offensive_tool_keyword = /\\rarce\.py/ nocase ascii wide
                        $string6_RaRCE_offensive_tool_keyword = "from rarce import exploit" nocase ascii wide
                        $string7_RaRCE_offensive_tool_keyword = "pip install rarce" nocase ascii wide
                        $string8_RaRCE_offensive_tool_keyword = "python -m rarce " nocase ascii wide
                        $string9_RaRCE_offensive_tool_keyword = /rarce\s.{0,1000}\.pdf\s.{0,1000}\.rar/ nocase ascii wide
                        $string10_RaRCE_offensive_tool_keyword = /rarce\s.{0,1000}\.rar/ nocase ascii wide
                        $string11_RaRCE_offensive_tool_keyword = /rarce\-1\.0\.0\.tar\.gz/ nocase ascii wide
                        $string12_RaRCE_offensive_tool_keyword = /rarce\-1\.0\.0\-py3\-none\-any\.whl/ nocase ascii wide
                        $string13_RaRCE_offensive_tool_keyword = /totally\slegit\spdf\.pdf/ nocase ascii wide

    condition:
        any of them
}