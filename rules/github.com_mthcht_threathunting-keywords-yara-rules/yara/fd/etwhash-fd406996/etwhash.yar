rule ETWHash
{
    meta:
        description = "Detection patterns for the tool 'ETWHash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ETWHash"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " EtwHash" nocase ascii wide
                        $string2 = "/ETWHash/" nocase ascii wide
                        $string3 = /\\ETWHash\./ nocase ascii wide
                        $string4 = /EtwHash\.exe/ nocase ascii wide
                        $string5 = /EtwHash\.git/ nocase ascii wide
                        $string6 = /ETWHash\.sln/ nocase ascii wide
                        $string7 = "nettitude/ETWHash" nocase ascii wide

    condition:
        any of them
}