rule godpotato {
  meta:
    description   = "Detection patterns for the tool 'godpotato' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "godpotato"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1  = /\\Godpotato\\/ nocase ascii wide
            $string2  = /BeichenDream\/GodPotato/ nocase ascii wide
            $string3  = /GodPotato\s\-/ nocase ascii wide
            $string4  = /GodPotato\.cs/ nocase ascii wide
            $string5  = /godpotato\.exe/ nocase ascii wide
            $string6  = /GodPotato\.git/ nocase ascii wide
            $string7  = /GodPotatoContext\.cs/ nocase ascii wide
            $string8  = /GodPotato\-master\.zip/ nocase ascii wide
            $string9  = /GodPotato\-NET.*\.exe/ nocase ascii wide
            $string10 = /GodPotatoUnmarshalTrigger\.cs/ nocase ascii wide
            $string11 = /SharpToken\.exe/ nocase ascii wide

  condition:
    any of them
}