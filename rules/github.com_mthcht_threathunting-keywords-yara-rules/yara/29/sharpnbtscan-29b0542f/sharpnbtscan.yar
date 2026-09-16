rule SharpNBTScan
{
    meta:
        description = "Detection patterns for the tool 'SharpNBTScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpNBTScan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpNBTScan\.git/ nocase ascii wide
                        $string2 = /\\SharpNBTScan\.sln/ nocase ascii wide
                        $string3 = /\\SharpNBTScan\-main/ nocase ascii wide
                        $string4 = ">SharpNBTScan<" nocase ascii wide
                        $string5 = "643de75be44ad32b70cee688f031ea110a078d6cffb79a48001717a5e0ebf909" nocase ascii wide
                        $string6 = "a398655a-d83f-46bf-8173-3ad16260d970" nocase ascii wide
                        $string7 = "a70c8c13e7173e19cb3aa035297921d69b0de0b6b495e052258e143ec7efed03" nocase ascii wide
                        $string8 = "BronzeTicket/SharpNBTScan" nocase ascii wide
                        $string9 = /SharpNBTScan\.exe/ nocase ascii wide

    condition:
        any of them
}