rule SharpGPOAbuse
{
    meta:
        description = "Detection patterns for the tool 'SharpGPOAbuse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGPOAbuse"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-AddComputerTask\s\-\-TaskName\s.{0,1000}\s\-\-Author\s.{0,1000}\s\-\-Command\s.{0,1000}\s\-\-Arguments\s.{0,1000}\s\-\-GPOName\s/ nocase ascii wide
                        $string2 = /\s\-\-AddLocalAdmin\s\-\-UserAccount\s.{0,1000}\s\-\-GPOName\s/ nocase ascii wide
                        $string3 = /\s\-\-AddUserRights\s\-\-UserRights\s.{0,1000}\s\-\-UserAccount\s.{0,1000}\s\-\-GPOName\s/ nocase ascii wide
                        $string4 = /\s\-\-AddUserScript\s\-\-ScriptName\s.{0,1000}\s\-\-ScriptContents\s.{0,1000}\s\-\-GPOName\s/ nocase ascii wide
                        $string5 = /\s\-\-GPOName\s.{0,1000}\s\-\-FilterEnabled\s\-\-TargetDnsName\s/ nocase ascii wide
                        $string6 = /\sNewLocalAdmin\(/ nocase ascii wide
                        $string7 = /\\SharpGPOAbuse\.pdb/ nocase ascii wide
                        $string8 = ">SharpGPOAbuse<" nocase ascii wide
                        $string9 = "SharpGPOAbuse" nocase ascii wide
                        $string10 = "SharpGPOAbuse" nocase ascii wide
                        $string11 = /SharpGPOAbuse\.exe/ nocase ascii wide

    condition:
        any of them
}