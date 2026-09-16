rule dirtycow {
  meta:
    description   = "Detection patterns for the tool 'dirtycow' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "dirtycow"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /dirtycow/ nocase ascii wide

  condition:
    any of them
}