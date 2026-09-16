rule rule_RogueWinRM_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RogueWinRM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RogueWinRM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RogueWinRM_offensive_tool_keyword = /\/RogueWinRM\.git/ nocase ascii wide
                        $string2_RogueWinRM_offensive_tool_keyword = /\\RogueWinRM\.sln/ nocase ascii wide
                        $string3_RogueWinRM_offensive_tool_keyword = /\\RogueWinRM\\/ nocase ascii wide
                        $string4_RogueWinRM_offensive_tool_keyword = /\\windows\\temp\\nc64\.exe/ nocase ascii wide
                        $string5_RogueWinRM_offensive_tool_keyword = "antonioCoco/RogueWinRM" nocase ascii wide
                        $string6_RogueWinRM_offensive_tool_keyword = "B03A3AF9-9448-43FE-8CEE-5A2C43BFAC86" nocase ascii wide
                        $string7_RogueWinRM_offensive_tool_keyword = "ec260817672bcc48f734f89e9eac84ebc7903924b36f807caf58c6820c0e336c" nocase ascii wide
                        $string8_RogueWinRM_offensive_tool_keyword = "RogueWinRM " nocase ascii wide
                        $string9_RogueWinRM_offensive_tool_keyword = /RogueWinRM\.cpp/ nocase ascii wide
                        $string10_RogueWinRM_offensive_tool_keyword = /RogueWinRM\.exe/ nocase ascii wide
                        $string11_RogueWinRM_offensive_tool_keyword = /RogueWinRM\.zip/ nocase ascii wide
                        $string12_RogueWinRM_offensive_tool_keyword = /WinRM\salready\srunning\son\sport\s5985\.\sUnexploitable\!/ nocase ascii wide

    condition:
        any of them
}