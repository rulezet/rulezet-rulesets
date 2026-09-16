rule Ask4Creds
{
    meta:
        description = "Detection patterns for the tool 'Ask4Creds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ask4Creds"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sAsk4Creds\.ps1/ nocase ascii wide
                        $string2 = /\/Ask4Creds\.git/ nocase ascii wide
                        $string3 = /\/Ask4Creds\.ps1/ nocase ascii wide
                        $string4 = /\\Ask4Creds\.ps1/ nocase ascii wide
                        $string5 = "d3924d3bf6f59335a1e5453d80eaaa7404cea2e342105c3e69ddfb943aeb29c6" nocase ascii wide
                        $string6 = "Leo4j/Ask4Creds" nocase ascii wide

    condition:
        any of them
}