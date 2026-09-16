rule phishing_HTML_linter
{
    meta:
        description = "Detection patterns for the tool 'phishing-HTML-linter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phishing-HTML-linter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/VisualBasicObfuscator" nocase ascii wide
                        $string2 = /DancingRightToLeft\.py/ nocase ascii wide
                        $string3 = /gophish\-send\-mail\.py/ nocase ascii wide
                        $string4 = /MacroDetectSandbox\.vbs/ nocase ascii wide
                        $string5 = /Phish\-Creds\.ps1/ nocase ascii wide
                        $string6 = /phishing\-HTML\-linter\./ nocase ascii wide
                        $string7 = "RobustPentestMacro" nocase ascii wide
                        $string8 = /vba\-macro\-mac\-persistence\.vbs/ nocase ascii wide
                        $string9 = /vba\-windows\-persistence\.vbs/ nocase ascii wide
                        $string10 = /WMIPersistence\.vbs/ nocase ascii wide

    condition:
        any of them
}