rule SecLists {
  meta:
    description   = "Detection patterns for the tool 'SecLists' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "SecLists"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /SecLists/ nocase ascii wide

  condition:
    any of them
}