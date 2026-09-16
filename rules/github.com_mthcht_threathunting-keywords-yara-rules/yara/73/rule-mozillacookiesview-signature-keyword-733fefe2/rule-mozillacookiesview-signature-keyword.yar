rule rule_MozillaCookiesView_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'MozillaCookiesView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MozillaCookiesView"
        rule_category = "signature_keyword"

    strings:
                        $string1_MozillaCookiesView_signature_keyword = "Win64/MozillaCookiesView" nocase ascii wide

    condition:
        any of them
}