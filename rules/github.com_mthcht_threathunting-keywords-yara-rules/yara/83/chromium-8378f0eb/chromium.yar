rule chromium
{
    meta:
        description = "Detection patterns for the tool 'chromium' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chromium"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /brave.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
                        $string2 = /brave\.exe.{0,1000}\s\-\-load\-extension\=\\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
                        $string3 = /chrome.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
                        $string4 = /chrome\.exe.{0,1000}\s\-\-load\-extension\=\\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
                        $string5 = /msedge.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
                        $string6 = /msedge.{0,1000}\s\-\-headless\s\-\-disable\-gpu\s\-\-remote\-debugging\-port\=/ nocase ascii wide
                        $string7 = /msedge\.exe.{0,1000}\s\-\-load\-extension\=\\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
                        $string8 = /opera.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
                        $string9 = /opera\.exe.{0,1000}\s\-\-load\-extension\=\\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
                        $string10 = /vivaldi.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
                        $string11 = /vivaldi\.exe.{0,1000}\s\-\-load\-extension\=\\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide

    condition:
        any of them
}