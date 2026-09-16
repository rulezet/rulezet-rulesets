rule rule_tor_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'tor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tor"
        rule_category = "signature_keyword"

    strings:
                        $string1_tor_signature_keyword = "HackTool:Linux/TorDownload"

    condition:
        any of them
}