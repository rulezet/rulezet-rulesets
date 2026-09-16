rule UserEnum {
  meta:
    description   = "Detection patterns for the tool 'UserEnum' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "UserEnum"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /UserEnum/ nocase ascii wide

  condition:
    any of them
}