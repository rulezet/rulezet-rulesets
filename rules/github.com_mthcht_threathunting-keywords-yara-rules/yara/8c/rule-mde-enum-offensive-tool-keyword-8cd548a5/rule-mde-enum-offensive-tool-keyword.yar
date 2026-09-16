rule rule_MDE_Enum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MDE_Enum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MDE_Enum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MDE_Enum_offensive_tool_keyword = /\/MDE_Enum\.git/ nocase ascii wide
                        $string2_MDE_Enum_offensive_tool_keyword = /\[\+\]\sEnumerating\sASR\sRules\son\sLocal\sSystem/ nocase ascii wide
                        $string3_MDE_Enum_offensive_tool_keyword = /\[\+\]\sEnumerating\sASR\sRules\son\sRemote\sSystem\s/ nocase ascii wide
                        $string4_MDE_Enum_offensive_tool_keyword = /\\MDE_Enum\.csproj/ nocase ascii wide
                        $string5_MDE_Enum_offensive_tool_keyword = /\\MDE_Enum\.exe/ nocase ascii wide
                        $string6_MDE_Enum_offensive_tool_keyword = /\\MDE_Enum\\Program\.cs/ nocase ascii wide
                        $string7_MDE_Enum_offensive_tool_keyword = ">MDE_Enum<" nocase ascii wide
                        $string8_MDE_Enum_offensive_tool_keyword = "0xsp-SRD/MDE_Enum" nocase ascii wide
                        $string9_MDE_Enum_offensive_tool_keyword = "5EC16C3F-1E62-4661-8C20-504CB0E55441" nocase ascii wide
                        $string10_MDE_Enum_offensive_tool_keyword = "65cf6179c85728317f11460314779b365ba77199352a2b11624729f788daf6bc" nocase ascii wide
                        $string11_MDE_Enum_offensive_tool_keyword = "7b39a858a51efa5160d65300b9b89695caf33ec380f69a40cdb7f742e8f05a46" nocase ascii wide
                        $string12_MDE_Enum_offensive_tool_keyword = "MDE_Enum /local /asr" nocase ascii wide
                        $string13_MDE_Enum_offensive_tool_keyword = "MDE_Enum /local /paths" nocase ascii wide
                        $string14_MDE_Enum_offensive_tool_keyword = /ObjectQuery\(\\"SELECT\s.{0,1000}\sFROM\sMSFT_MpPreference\\"\)/ nocase ascii wide
                        $string15_MDE_Enum_offensive_tool_keyword = "Remote System - MDE_Enum " nocase ascii wide
                        $string16_MDE_Enum_offensive_tool_keyword = "-Retrieve Defender ASR Triggered Events -" nocase ascii wide
                        $string17_MDE_Enum_offensive_tool_keyword = "-Retrieve Defender Exclusion Paths Using Event Logs -" nocase ascii wide
                        $string18_MDE_Enum_offensive_tool_keyword = "using MDE_Enum;" nocase ascii wide
                        $string19_MDE_Enum_offensive_tool_keyword = "WindowsDefenderEventLog_Enum " nocase ascii wide

    condition:
        any of them
}