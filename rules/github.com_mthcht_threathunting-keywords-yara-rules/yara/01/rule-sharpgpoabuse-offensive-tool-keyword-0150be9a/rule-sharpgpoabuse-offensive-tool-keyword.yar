rule rule_SharpGPOAbuse_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpGPOAbuse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGPOAbuse"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpGPOAbuse_offensive_tool_keyword = /\s\-\-AddComputerTask\s\-\-TaskName\s.{0,1000}\s\-\-Author\s.{0,1000}\s\-\-Command\s.{0,1000}\s\-\-Arguments\s.{0,1000}\s\-\-GPOName\s/ nocase ascii wide
                        $string2_SharpGPOAbuse_offensive_tool_keyword = /\s\-\-AddLocalAdmin\s\-\-UserAccount\s.{0,1000}\s\-\-GPOName\s/ nocase ascii wide
                        $string3_SharpGPOAbuse_offensive_tool_keyword = /\s\-\-AddUserRights\s\-\-UserRights\s.{0,1000}\s\-\-UserAccount\s.{0,1000}\s\-\-GPOName\s/ nocase ascii wide
                        $string4_SharpGPOAbuse_offensive_tool_keyword = /\s\-\-AddUserScript\s\-\-ScriptName\s.{0,1000}\s\-\-ScriptContents\s.{0,1000}\s\-\-GPOName\s/ nocase ascii wide
                        $string5_SharpGPOAbuse_offensive_tool_keyword = /\s\-\-GPOName\s.{0,1000}\s\-\-FilterEnabled\s\-\-TargetDnsName\s/ nocase ascii wide
                        $string6_SharpGPOAbuse_offensive_tool_keyword = /\sNewLocalAdmin\(/ nocase ascii wide
                        $string7_SharpGPOAbuse_offensive_tool_keyword = /\\SharpGPOAbuse\.pdb/ nocase ascii wide
                        $string8_SharpGPOAbuse_offensive_tool_keyword = ">SharpGPOAbuse<" nocase ascii wide
                        $string9_SharpGPOAbuse_offensive_tool_keyword = "SharpGPOAbuse" nocase ascii wide
                        $string10_SharpGPOAbuse_offensive_tool_keyword = "SharpGPOAbuse" nocase ascii wide
                        $string11_SharpGPOAbuse_offensive_tool_keyword = /SharpGPOAbuse\.exe/ nocase ascii wide

    condition:
        any of them
}