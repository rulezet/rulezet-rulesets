rule index_allocation {
  meta:
    description   = "Detection patterns for the tool '$index_allocation' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "$index_allocation"
    rule_category = "greyware_tool_keyword"

  strings:
            $string1 = /\.\.\.::\$index_allocation/ nocase ascii wide
            $string2 = /cd\s.*\.::\$index_allocation/ nocase ascii wide
            $string3 = /md\s.*\.::\$index_allocation/ nocase ascii wide

  condition:
    any of them
}