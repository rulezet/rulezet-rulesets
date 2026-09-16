rule rule_SharpRODC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpRODC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRODC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpRODC_offensive_tool_keyword = /\/SharpRODC\.git/ nocase ascii wide
                        $string2_SharpRODC_offensive_tool_keyword = /\\SharpRODC\./ nocase ascii wide
                        $string3_SharpRODC_offensive_tool_keyword = /\\SharpRODC\\/ nocase ascii wide
                        $string4_SharpRODC_offensive_tool_keyword = "62e779d3d44b32644b427335bb091880b637ed5dd3c01ec2ecd9c732a5d17539" nocase ascii wide
                        $string5_SharpRODC_offensive_tool_keyword = "69e92737993cca7f4757a5a3dc027b1f85ee6d836f18f6433332d9d269b9262f" nocase ascii wide
                        $string6_SharpRODC_offensive_tool_keyword = "987ebc109f9bb594b780a59dbe5f5b5c3694f5ac21bb0bd044b4e06ccb64bdab" nocase ascii wide
                        $string7_SharpRODC_offensive_tool_keyword = "9ca9d965d2d159763c2ca4431a1fa6597ca6633f443732139340341c77f6a39f" nocase ascii wide
                        $string8_SharpRODC_offensive_tool_keyword = "D305F8A3-019A-4CDF-909C-069D5B483613" nocase ascii wide
                        $string9_SharpRODC_offensive_tool_keyword = "Get-ADComputer RODC -Properties msDS-RevealedList" nocase ascii wide
                        $string10_SharpRODC_offensive_tool_keyword = /https\:\/\/whoamianony\.top\/posts\// nocase ascii wide
                        $string11_SharpRODC_offensive_tool_keyword = /Set\-DomainObject\s\-Identity\s\'CN\=Allowed\sRODC\sPassword\sReplication\sGroup.{0,1000}\s\-Set\s\@\{\'member\'\=\@\(/ nocase ascii wide
                        $string12_SharpRODC_offensive_tool_keyword = /Set\-DomainObject\s\-Identity\s\'CN\=Denied\sRODC\sPassword\sReplication\sGroup.{0,1000}\s\-Clear\s\'member\'/ nocase ascii wide
                        $string13_SharpRODC_offensive_tool_keyword = /Set\-DomainObject\s\-Identity\s\'CN\=RODC.{0,1000}\s\-Set\s\@\{\'msDS\-NeverRevealGroup\'\=\@\(/ nocase ascii wide
                        $string14_SharpRODC_offensive_tool_keyword = /SharpRODC\.exe/ nocase ascii wide
                        $string15_SharpRODC_offensive_tool_keyword = /SharpRODC\.pdb/ nocase ascii wide
                        $string16_SharpRODC_offensive_tool_keyword = "wh0amitz/SharpRODC" nocase ascii wide

    condition:
        any of them
}