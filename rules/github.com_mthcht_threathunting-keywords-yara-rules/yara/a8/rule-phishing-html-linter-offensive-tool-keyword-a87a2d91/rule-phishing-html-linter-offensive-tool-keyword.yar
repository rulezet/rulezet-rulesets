rule rule_phishing_HTML_linter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'phishing-HTML-linter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phishing-HTML-linter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_phishing_HTML_linter_offensive_tool_keyword = "/VisualBasicObfuscator" nocase ascii wide
                        $string2_phishing_HTML_linter_offensive_tool_keyword = /DancingRightToLeft\.py/ nocase ascii wide
                        $string3_phishing_HTML_linter_offensive_tool_keyword = /gophish\-send\-mail\.py/ nocase ascii wide
                        $string4_phishing_HTML_linter_offensive_tool_keyword = /MacroDetectSandbox\.vbs/ nocase ascii wide
                        $string5_phishing_HTML_linter_offensive_tool_keyword = /Phish\-Creds\.ps1/ nocase ascii wide
                        $string6_phishing_HTML_linter_offensive_tool_keyword = /phishing\-HTML\-linter\./ nocase ascii wide
                        $string7_phishing_HTML_linter_offensive_tool_keyword = "RobustPentestMacro" nocase ascii wide
                        $string8_phishing_HTML_linter_offensive_tool_keyword = /vba\-macro\-mac\-persistence\.vbs/ nocase ascii wide
                        $string9_phishing_HTML_linter_offensive_tool_keyword = /vba\-windows\-persistence\.vbs/ nocase ascii wide
                        $string10_phishing_HTML_linter_offensive_tool_keyword = /WMIPersistence\.vbs/ nocase ascii wide

    condition:
        any of them
}