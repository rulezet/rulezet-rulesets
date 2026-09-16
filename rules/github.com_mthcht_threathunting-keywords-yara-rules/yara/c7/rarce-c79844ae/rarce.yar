rule RaRCE
{
    meta:
        description = "Detection patterns for the tool 'RaRCE' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RaRCE"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " CVE-2023-38831-RaRCE" nocase ascii wide
                        $string2 = /\srarce\.py/ nocase ascii wide
                        $string3 = "/CVE-2023-38831-RaRCE" nocase ascii wide
                        $string4 = /\/rarce\.py/ nocase ascii wide
                        $string5 = /\\rarce\.py/ nocase ascii wide
                        $string6 = "from rarce import exploit" nocase ascii wide
                        $string7 = "pip install rarce" nocase ascii wide
                        $string8 = "python -m rarce " nocase ascii wide
                        $string9 = /rarce\s.{0,1000}\.pdf\s.{0,1000}\.rar/ nocase ascii wide
                        $string10 = /rarce\s.{0,1000}\.rar/ nocase ascii wide
                        $string11 = /rarce\-1\.0\.0\.tar\.gz/ nocase ascii wide
                        $string12 = /rarce\-1\.0\.0\-py3\-none\-any\.whl/ nocase ascii wide
                        $string13 = /totally\slegit\spdf\.pdf/ nocase ascii wide

    condition:
        any of them
}