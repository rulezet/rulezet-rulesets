rule rule_SharpSQL_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSQL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSQL"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSQL_offensive_tool_keyword = /\.exe\sEnable\-LinkedCmdshell/ nocase ascii wide
                        $string2_SharpSQL_offensive_tool_keyword = /\.exe\sGet\-Hash\s\-Instance\s.{0,1000}\s\-ip\s/ nocase ascii wide
                        $string3_SharpSQL_offensive_tool_keyword = /\.exe\sGet\-LinkedServers\s\-Instance\s/ nocase ascii wide
                        $string4_SharpSQL_offensive_tool_keyword = /\.exe\sGet\-SQLInstanceDomain/ nocase ascii wide
                        $string5_SharpSQL_offensive_tool_keyword = /\.exe\sGet\-Sysadmins\s\-Instance\s/ nocase ascii wide
                        $string6_SharpSQL_offensive_tool_keyword = /\.exe\sGet\-UserPrivs\s\-Instance\s/ nocase ascii wide
                        $string7_SharpSQL_offensive_tool_keyword = /\.exe\sInvoke\-CLRAsm\s\-Instance\s.{0,1000}\s\-Command\s/ nocase ascii wide
                        $string8_SharpSQL_offensive_tool_keyword = /\.exe\sInvoke\-LinkedOSCmd\s\-Instance\s/ nocase ascii wide
                        $string9_SharpSQL_offensive_tool_keyword = /\.exe\sInvoke\-OLEObject\s/ nocase ascii wide
                        $string10_SharpSQL_offensive_tool_keyword = /\.exe\sInvoke\-OSCmd\s\-Instance\s.{0,1000}\s\-Command\s/ nocase ascii wide
                        $string11_SharpSQL_offensive_tool_keyword = /\.exe\sInvoke\-UserImpersonation\s/ nocase ascii wide
                        $string12_SharpSQL_offensive_tool_keyword = /\/SharpSQL\.exe/ nocase ascii wide
                        $string13_SharpSQL_offensive_tool_keyword = /\\SharpSQL\.exe/ nocase ascii wide
                        $string14_SharpSQL_offensive_tool_keyword = /\\SharpSQL\.pdb/ nocase ascii wide
                        $string15_SharpSQL_offensive_tool_keyword = ">SharpSQL<" nocase ascii wide
                        $string16_SharpSQL_offensive_tool_keyword = "SharpSQL by @mlcsec" nocase ascii wide

    condition:
        any of them
}