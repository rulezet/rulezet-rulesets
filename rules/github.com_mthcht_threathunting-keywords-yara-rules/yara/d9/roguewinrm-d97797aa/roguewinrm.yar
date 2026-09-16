rule RogueWinRM
{
    meta:
        description = "Detection patterns for the tool 'RogueWinRM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RogueWinRM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/RogueWinRM\.git/ nocase ascii wide
                        $string2 = /\\RogueWinRM\.sln/ nocase ascii wide
                        $string3 = /\\RogueWinRM\\/ nocase ascii wide
                        $string4 = /\\windows\\temp\\nc64\.exe/ nocase ascii wide
                        $string5 = "antonioCoco/RogueWinRM" nocase ascii wide
                        $string6 = "B03A3AF9-9448-43FE-8CEE-5A2C43BFAC86" nocase ascii wide
                        $string7 = "ec260817672bcc48f734f89e9eac84ebc7903924b36f807caf58c6820c0e336c" nocase ascii wide
                        $string8 = "RogueWinRM " nocase ascii wide
                        $string9 = /RogueWinRM\.cpp/ nocase ascii wide
                        $string10 = /RogueWinRM\.exe/ nocase ascii wide
                        $string11 = /RogueWinRM\.zip/ nocase ascii wide
                        $string12 = /WinRM\salready\srunning\son\sport\s5985\.\sUnexploitable\!/ nocase ascii wide

    condition:
        any of them
}