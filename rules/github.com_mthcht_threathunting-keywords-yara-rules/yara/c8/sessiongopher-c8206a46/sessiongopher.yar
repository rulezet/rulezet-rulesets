rule SessionGopher
{
    meta:
        description = "Detection patterns for the tool 'SessionGopher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionGopher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sSessionGopher\.ps1/ nocase ascii wide
                        $string2 = "\"Saved in session, but master password prevents plaintext recovery\"" nocase ascii wide
                        $string3 = /\$fct\s\=\sGet\-Content\s\-Encoding\sbyte\s\-Path\s/ nocase ascii wide
                        $string4 = /\/SessionGopher\.git/ nocase ascii wide
                        $string5 = /\/SessionGopher\.ps1/ nocase ascii wide
                        $string6 = /\\PuTTY\sppk\sFiles\.csv/ nocase ascii wide
                        $string7 = /\\SessionGopher\.ps1/ nocase ascii wide
                        $string8 = /\\SuperPuTTY\.csv/ nocase ascii wide
                        $string9 = "Arvanaghi/SessionGopher" nocase ascii wide
                        $string10 = "Invoke-SessionGopher" nocase ascii wide

    condition:
        any of them
}