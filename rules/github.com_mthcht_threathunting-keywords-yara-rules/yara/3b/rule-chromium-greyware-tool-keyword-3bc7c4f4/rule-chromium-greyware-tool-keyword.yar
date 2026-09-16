rule rule_chromium_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chromium' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chromium"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_chromium_greyware_tool_keyword = /brave.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
                        $string2_chromium_greyware_tool_keyword = /brave\.exe.{0,1000}\s\-\-load\-extension\=\\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
                        $string3_chromium_greyware_tool_keyword = /chrome.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
                        $string4_chromium_greyware_tool_keyword = /chrome\.exe.{0,1000}\s\-\-load\-extension\=\\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
                        $string5_chromium_greyware_tool_keyword = /msedge.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
                        $string6_chromium_greyware_tool_keyword = /msedge.{0,1000}\s\-\-headless\s\-\-disable\-gpu\s\-\-remote\-debugging\-port\=/ nocase ascii wide
                        $string7_chromium_greyware_tool_keyword = /msedge\.exe.{0,1000}\s\-\-load\-extension\=\\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
                        $string8_chromium_greyware_tool_keyword = /opera.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
                        $string9_chromium_greyware_tool_keyword = /opera\.exe.{0,1000}\s\-\-load\-extension\=\\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
                        $string10_chromium_greyware_tool_keyword = /vivaldi.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
                        $string11_chromium_greyware_tool_keyword = /vivaldi\.exe.{0,1000}\s\-\-load\-extension\=\\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide

    condition:
        any of them
}