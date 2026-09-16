rule hashview
{
    meta:
        description = "Detection patterns for the tool 'hashview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hashview"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\shashview\.py/ nocase ascii wide
                        $string2 = " hashview-agent " nocase ascii wide
                        $string3 = /\.\/hashview\//
                        $string4 = /\/hashview\.py/ nocase ascii wide
                        $string5 = /\\hashview\.py/ nocase ascii wide
                        $string6 = "DoNotUseThisPassword123!" nocase ascii wide
                        $string7 = /hashview.{0,1000}\@.{0,1000}localhost/ nocase ascii wide
                        $string8 = /hashview\/config\.conf/ nocase ascii wide
                        $string9 = "hashview/hashview" nocase ascii wide
                        $string10 = /hashview\-agent\..{0,1000}\.tgz/ nocase ascii wide
                        $string11 = /hashview\-agent\.py/ nocase ascii wide
                        $string12 = /rockyou\.txt\.gz/ nocase ascii wide
                        $string13 = /wordlists\/dynamic\-all\.txt/ nocase ascii wide
                        $string14 = /wordlists\/rockyou\.txt\'/ nocase ascii wide

    condition:
        any of them
}