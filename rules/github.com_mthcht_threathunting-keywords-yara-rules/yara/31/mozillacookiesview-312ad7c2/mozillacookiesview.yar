rule MozillaCookiesView
{
    meta:
        description = "Detection patterns for the tool 'MozillaCookiesView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MozillaCookiesView"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "Win64/MozillaCookiesView" nocase ascii wide

    condition:
        any of them
}