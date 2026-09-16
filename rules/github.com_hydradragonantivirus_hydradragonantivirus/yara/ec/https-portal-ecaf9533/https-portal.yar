rule https_portal {
  meta:
    description   = "Detection patterns for the tool 'https-portal' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "https-portal"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /https\-portal/ nocase ascii wide

  condition:
    any of them
}