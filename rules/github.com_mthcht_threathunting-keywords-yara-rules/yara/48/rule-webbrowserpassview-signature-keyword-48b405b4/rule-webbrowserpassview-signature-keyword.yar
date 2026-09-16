rule rule_webBrowserPassView_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'webBrowserPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webBrowserPassView"
        rule_category = "signature_keyword"

    strings:
                        $string1_webBrowserPassView_signature_keyword = /HackTool\.Win32\.NirsoftPT\.SM/ nocase ascii wide
                        $string2_webBrowserPassView_signature_keyword = /PSWTool\.Win32\.PassView/ nocase ascii wide
                        $string3_webBrowserPassView_signature_keyword = "PUA:Win32/PassShow" nocase ascii wide
                        $string4_webBrowserPassView_signature_keyword = "Riskware/WebBrowserPassView" nocase ascii wide

    condition:
        any of them
}