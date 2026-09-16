rule PowerShdll0 {
  meta:
    description   = "Detection patterns for the tool 'PowerShdll' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "PowerShdll"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /36EBF9AA\-2F37\-4F1D\-A2F1\-F2A45DEEAF21/ nocase ascii wide
            $string2 = /5067F916\-9971\-47D6\-BBCB\-85FB3982584F/ nocase ascii wide
            $string3 = /PowerShdll/ nocase ascii wide

  condition:
    any of them
}