rule KPortScan0 {
  meta:
    description   = "Detection patterns for the tool 'KPortScan' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "KPortScan"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1  = /\/rdp_brute\.git/ nocase ascii wide
            $string2  = /\\AppData\\Local\\Temp\\KPortScan/ nocase ascii wide
            $string3  = /\\KPortScan\s3\.0\\/ nocase ascii wide
            $string4  = /\\KPortScan\\/ nocase ascii wide
            $string5  = "080c6108c3bd0f8a43d5647db36dc434032842339f0ba38ad1ff62f72999c4e5" nocase ascii wide
            $string6  = /KPortScan\.exe/ nocase ascii wide
            $string7  = /KPortScan\.rar/ nocase ascii wide
            $string8  = /KPortScan\.zip/ nocase ascii wide
            $string9  = /KPortScan3\.exe/ nocase ascii wide
            $string10 = "stardust50578/rdp_brute" nocase ascii wide

  condition:
    any of them
}