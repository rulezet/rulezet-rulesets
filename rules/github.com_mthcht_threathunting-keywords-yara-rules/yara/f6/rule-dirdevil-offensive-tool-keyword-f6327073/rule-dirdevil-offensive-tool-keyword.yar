rule rule_dirdevil_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dirdevil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirdevil"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dirdevil_offensive_tool_keyword = /\sdirdevil\.ps1/ nocase ascii wide
                        $string2_dirdevil_offensive_tool_keyword = /\sdirdevil_decoder_mini\.ps1/ nocase ascii wide
                        $string3_dirdevil_offensive_tool_keyword = /\sdirdevil_decoder_only\.ps1/ nocase ascii wide
                        $string4_dirdevil_offensive_tool_keyword = /\/dirdevil\.git/ nocase ascii wide
                        $string5_dirdevil_offensive_tool_keyword = /\/dirdevil\.ps1/ nocase ascii wide
                        $string6_dirdevil_offensive_tool_keyword = /\/dirdevil_decoder_mini\.ps1/ nocase ascii wide
                        $string7_dirdevil_offensive_tool_keyword = /\/dirdevil_decoder_only\.ps1/ nocase ascii wide
                        $string8_dirdevil_offensive_tool_keyword = "@2024 nyxgeek - TrustedSec" nocase ascii wide
                        $string9_dirdevil_offensive_tool_keyword = /\\dirdevil\.ps1/ nocase ascii wide
                        $string10_dirdevil_offensive_tool_keyword = /\\dirdevil_decoder_mini\.ps1/ nocase ascii wide
                        $string11_dirdevil_offensive_tool_keyword = /\\dirdevil_decoder_only\.ps1/ nocase ascii wide
                        $string12_dirdevil_offensive_tool_keyword = /\\trustedsec\\Downloads\\putty\.exe/ nocase ascii wide
                        $string13_dirdevil_offensive_tool_keyword = "0ad1f9bb7c3b296339d3c3f9bb4338b79bfb9f051fbb8749c411c44195e68d35" nocase ascii wide
                        $string14_dirdevil_offensive_tool_keyword = "3e6740a3e67c207dc53df0daf1c5717def2b267119c75ff0cf6e36585efc332a" nocase ascii wide
                        $string15_dirdevil_offensive_tool_keyword = "41f73755bc80ff028571e3496dd851447cc69f428045223deb717173e5c44e69" nocase ascii wide
                        $string16_dirdevil_offensive_tool_keyword = "dirdevil - PowerShell to hide data in directory structures" nocase ascii wide
                        $string17_dirdevil_offensive_tool_keyword = "nyxgeek/dirdevil" nocase ascii wide

    condition:
        any of them
}