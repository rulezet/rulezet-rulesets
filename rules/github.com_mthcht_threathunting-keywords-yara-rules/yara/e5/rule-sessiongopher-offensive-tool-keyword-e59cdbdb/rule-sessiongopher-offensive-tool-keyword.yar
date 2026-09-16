rule rule_SessionGopher_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SessionGopher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionGopher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SessionGopher_offensive_tool_keyword = /\sSessionGopher\.ps1/ nocase ascii wide
                        $string2_SessionGopher_offensive_tool_keyword = "\"Saved in session, but master password prevents plaintext recovery\"" nocase ascii wide
                        $string3_SessionGopher_offensive_tool_keyword = /\$fct\s\=\sGet\-Content\s\-Encoding\sbyte\s\-Path\s/ nocase ascii wide
                        $string4_SessionGopher_offensive_tool_keyword = /\/SessionGopher\.git/ nocase ascii wide
                        $string5_SessionGopher_offensive_tool_keyword = /\/SessionGopher\.ps1/ nocase ascii wide
                        $string6_SessionGopher_offensive_tool_keyword = /\\PuTTY\sppk\sFiles\.csv/ nocase ascii wide
                        $string7_SessionGopher_offensive_tool_keyword = /\\SessionGopher\.ps1/ nocase ascii wide
                        $string8_SessionGopher_offensive_tool_keyword = /\\SuperPuTTY\.csv/ nocase ascii wide
                        $string9_SessionGopher_offensive_tool_keyword = "Arvanaghi/SessionGopher" nocase ascii wide
                        $string10_SessionGopher_offensive_tool_keyword = "Invoke-SessionGopher" nocase ascii wide

    condition:
        any of them
}