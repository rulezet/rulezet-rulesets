rule rule_ChaiLdr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ChaiLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ChaiLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ChaiLdr_offensive_tool_keyword = /\!\]\sAPC\sInjection\svia\sSyscalls\sfailed\!/ nocase ascii wide
                        $string2_ChaiLdr_offensive_tool_keyword = /\/ChaiLdr\.exe/ nocase ascii wide
                        $string3_ChaiLdr_offensive_tool_keyword = /\/ChaiLdr\.git/ nocase ascii wide
                        $string4_ChaiLdr_offensive_tool_keyword = /\\ChaiLdr\.exe/ nocase ascii wide
                        $string5_ChaiLdr_offensive_tool_keyword = /\\ChaiLdr\-main/ nocase ascii wide
                        $string6_ChaiLdr_offensive_tool_keyword = "06a80d02597302885c6a7ed373187e751e82878f71826962e0c09e74647326d5" nocase ascii wide
                        $string7_ChaiLdr_offensive_tool_keyword = "0cd8f2bd40fdca1eb41c8317b86b1382f1cbf57e2a7537fd731c8541132bef60" nocase ascii wide
                        $string8_ChaiLdr_offensive_tool_keyword = "658318b022bfa0408ef73d5a1333cdfc5fec5295a0aaa75c81b54f46b5d87ad8" nocase ascii wide
                        $string9_ChaiLdr_offensive_tool_keyword = "6746881860057860fe384c046a89cdf6f5e3bbd014793b6e0d029f160b4119cf" nocase ascii wide
                        $string10_ChaiLdr_offensive_tool_keyword = "9ea66594805d5e7b8a1abc876f99d7ce1de87936902a3f7726f5f0188778c874" nocase ascii wide
                        $string11_ChaiLdr_offensive_tool_keyword = "c030cc4102e6bd16e8f55a5030a440f6ee5f411ad86b1c3af56b44e53cda14f6" nocase ascii wide
                        $string12_ChaiLdr_offensive_tool_keyword = "cd4d53a9-2db8-4408-90a0-896b2bc4c9f8" nocase ascii wide
                        $string13_ChaiLdr_offensive_tool_keyword = "Cipher7/ChaiLdr" nocase ascii wide
                        $string14_ChaiLdr_offensive_tool_keyword = /syswhispers\-apc\.c/ nocase ascii wide
                        $string15_ChaiLdr_offensive_tool_keyword = /syswhispers\-apc\.h/ nocase ascii wide
                        $string16_ChaiLdr_offensive_tool_keyword = /syswhispers\-apc\-asm\.x64\.asm/ nocase ascii wide

    condition:
        any of them
}