rule xspy__display {
  meta:
    description   = "Detection patterns for the tool 'xspy -display' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "xspy -display"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /xspy\s\-display/ nocase ascii wide

  condition:
    any of them
}