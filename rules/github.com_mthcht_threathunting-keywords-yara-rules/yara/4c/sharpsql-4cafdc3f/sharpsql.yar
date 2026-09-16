rule SharpSQL
{
    meta:
        description = "Detection patterns for the tool 'SharpSQL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSQL"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\sEnable\-LinkedCmdshell/ nocase ascii wide
                        $string2 = /\.exe\sGet\-Hash\s\-Instance\s.{0,1000}\s\-ip\s/ nocase ascii wide
                        $string3 = /\.exe\sGet\-LinkedServers\s\-Instance\s/ nocase ascii wide
                        $string4 = /\.exe\sGet\-SQLInstanceDomain/ nocase ascii wide
                        $string5 = /\.exe\sGet\-Sysadmins\s\-Instance\s/ nocase ascii wide
                        $string6 = /\.exe\sGet\-UserPrivs\s\-Instance\s/ nocase ascii wide
                        $string7 = /\.exe\sInvoke\-CLRAsm\s\-Instance\s.{0,1000}\s\-Command\s/ nocase ascii wide
                        $string8 = /\.exe\sInvoke\-LinkedOSCmd\s\-Instance\s/ nocase ascii wide
                        $string9 = /\.exe\sInvoke\-OLEObject\s/ nocase ascii wide
                        $string10 = /\.exe\sInvoke\-OSCmd\s\-Instance\s.{0,1000}\s\-Command\s/ nocase ascii wide
                        $string11 = /\.exe\sInvoke\-UserImpersonation\s/ nocase ascii wide
                        $string12 = /\/SharpSQL\.exe/ nocase ascii wide
                        $string13 = /\\SharpSQL\.exe/ nocase ascii wide
                        $string14 = /\\SharpSQL\.pdb/ nocase ascii wide
                        $string15 = ">SharpSQL<" nocase ascii wide
                        $string16 = "SharpSQL by @mlcsec" nocase ascii wide

    condition:
        any of them
}