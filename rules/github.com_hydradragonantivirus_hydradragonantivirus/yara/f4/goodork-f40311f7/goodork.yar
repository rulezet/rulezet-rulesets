rule GooDork {
  meta:
    description   = "Detection patterns for the tool 'GooDork' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "GooDork"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /GooDork/ nocase ascii wide

  condition:
    any of them
}