rule webBrowserPassView
{
    meta:
        description = "Detection patterns for the tool 'webBrowserPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webBrowserPassView"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.Win32\.NirsoftPT\.SM/ nocase ascii wide
                        $string2 = /PSWTool\.Win32\.PassView/ nocase ascii wide
                        $string3 = "PUA:Win32/PassShow" nocase ascii wide
                        $string4 = "Riskware/WebBrowserPassView" nocase ascii wide

    condition:
        any of them
}