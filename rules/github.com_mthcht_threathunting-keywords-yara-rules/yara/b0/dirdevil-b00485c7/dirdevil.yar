rule dirdevil
{
    meta:
        description = "Detection patterns for the tool 'dirdevil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirdevil"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdirdevil\.ps1/ nocase ascii wide
                        $string2 = /\sdirdevil_decoder_mini\.ps1/ nocase ascii wide
                        $string3 = /\sdirdevil_decoder_only\.ps1/ nocase ascii wide
                        $string4 = /\/dirdevil\.git/ nocase ascii wide
                        $string5 = /\/dirdevil\.ps1/ nocase ascii wide
                        $string6 = /\/dirdevil_decoder_mini\.ps1/ nocase ascii wide
                        $string7 = /\/dirdevil_decoder_only\.ps1/ nocase ascii wide
                        $string8 = "@2024 nyxgeek - TrustedSec" nocase ascii wide
                        $string9 = /\\dirdevil\.ps1/ nocase ascii wide
                        $string10 = /\\dirdevil_decoder_mini\.ps1/ nocase ascii wide
                        $string11 = /\\dirdevil_decoder_only\.ps1/ nocase ascii wide
                        $string12 = /\\trustedsec\\Downloads\\putty\.exe/ nocase ascii wide
                        $string13 = "0ad1f9bb7c3b296339d3c3f9bb4338b79bfb9f051fbb8749c411c44195e68d35" nocase ascii wide
                        $string14 = "3e6740a3e67c207dc53df0daf1c5717def2b267119c75ff0cf6e36585efc332a" nocase ascii wide
                        $string15 = "41f73755bc80ff028571e3496dd851447cc69f428045223deb717173e5c44e69" nocase ascii wide
                        $string16 = "dirdevil - PowerShell to hide data in directory structures" nocase ascii wide
                        $string17 = "nyxgeek/dirdevil" nocase ascii wide

    condition:
        any of them
}