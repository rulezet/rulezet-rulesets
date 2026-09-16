rule rule_Dirty_Vanity_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Dirty-Vanity' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dirty-Vanity"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Dirty_Vanity_offensive_tool_keyword = /\#include\s\\"DirtyVanity\.h\\"/ nocase ascii wide
                        $string2_Dirty_Vanity_offensive_tool_keyword = /\/Dirty\-Vanity\.git/ nocase ascii wide
                        $string3_Dirty_Vanity_offensive_tool_keyword = /\/k\smsg\s.{0,1000}\sHello\sfrom\sDirty\sVanity/ nocase ascii wide
                        $string4_Dirty_Vanity_offensive_tool_keyword = /\/k\smsg\s.{0,1000}\sHello\sfrom\sTam\.Men/ nocase ascii wide
                        $string5_Dirty_Vanity_offensive_tool_keyword = /\/vanity\.exe/ nocase ascii wide
                        $string6_Dirty_Vanity_offensive_tool_keyword = /\[\+\]\sNo\sPID\sprovided\,\screating\sa\snew\scalc\.exe\sprocess\sand\susing\sits\sPID/ nocase ascii wide
                        $string7_Dirty_Vanity_offensive_tool_keyword = /\[\+\]\sSuccesfuly\swrote\sshellcode\sto\svictim\.\sabout\sto\sstart\sthe\sMirroring/ nocase ascii wide
                        $string8_Dirty_Vanity_offensive_tool_keyword = /\[\+\]\sUSAGE\:\sDirtyVanity\s/ nocase ascii wide
                        $string9_Dirty_Vanity_offensive_tool_keyword = /\\DirtyVanity\.cpp/ nocase ascii wide
                        $string10_Dirty_Vanity_offensive_tool_keyword = /\\DirtyVanity\.sln/ nocase ascii wide
                        $string11_Dirty_Vanity_offensive_tool_keyword = /\\vanity\.exe/ nocase ascii wide
                        $string12_Dirty_Vanity_offensive_tool_keyword = "2C809982-78A1-4F1C-B0E8-C957C93B242F" nocase ascii wide
                        $string13_Dirty_Vanity_offensive_tool_keyword = "2d837b6c7343aec8123077db07d3fb8f9f7e44c5b108bf713380b17dac7569b9" nocase ascii wide
                        $string14_Dirty_Vanity_offensive_tool_keyword = "53891DF6-3F6D-DE4B-A8CD-D89E94D0C8CD" nocase ascii wide
                        $string15_Dirty_Vanity_offensive_tool_keyword = "deepinstinct/Dirty-Vanity" nocase ascii wide
                        $string16_Dirty_Vanity_offensive_tool_keyword = /DirtyVanity\.exe/ nocase ascii wide
                        $string17_Dirty_Vanity_offensive_tool_keyword = "e977ee0a5a2f0063f34b0b744b0753e65990e9467843b0dec3c281a6d4a2e009" nocase ascii wide

    condition:
        any of them
}