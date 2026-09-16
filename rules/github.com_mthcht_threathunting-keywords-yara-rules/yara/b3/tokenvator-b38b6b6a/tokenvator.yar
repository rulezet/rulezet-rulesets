rule Tokenvator
{
    meta:
        description = "Detection patterns for the tool 'Tokenvator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tokenvator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sClone_Token\s\/Process\:.{0,1000}\s\/Command\:/ nocase ascii wide
                        $string2 = /\ssteal_token\s\/process\:.{0,1000}\s\/command\:/ nocase ascii wide
                        $string3 = " tokenvator " nocase ascii wide
                        $string4 = /\/MonkeyWorks\.git/ nocase ascii wide
                        $string5 = "/ServiceName:TokenDriver" nocase ascii wide
                        $string6 = "/Tokenvator/" nocase ascii wide
                        $string7 = /\\KernelTokens\.sys/ nocase ascii wide
                        $string8 = /\\Tokenvator\\/ nocase ascii wide
                        $string9 = "0xbadjuju/Tokenvator" nocase ascii wide
                        $string10 = /Add_Privilege\s\/Process\:.{0,1000}\s\/Privilege\:/ nocase ascii wide
                        $string11 = /BypassUAC\s.{0,1000}\.exe/ nocase ascii wide
                        $string12 = /Disable_Privilege\s\/Process\:.{0,1000}\s\/Privilege\:/ nocase ascii wide
                        $string13 = /Enable_Privilege\s\/Process\:.{0,1000}\s\/Privilege\:/ nocase ascii wide
                        $string14 = "Enumeration/DesktopACL" nocase ascii wide
                        $string15 = /Enumeration\\DesktopAC/ nocase ascii wide
                        $string16 = "List_Privileges /Process:powershell" nocase ascii wide
                        $string17 = "Nuke_Privileges /Process:" nocase ascii wide
                        $string18 = /Plugins\\AccessTokens\\TokenDriver/ nocase ascii wide
                        $string19 = /Plugins\\AccessTokens\\TokenManipulation/ nocase ascii wide
                        $string20 = /Plugins\\Execution\\PSExec/ nocase ascii wide
                        $string21 = /Remove_Privilege\s\/Process\:.{0,1000}\s\/Privilege\:/ nocase ascii wide
                        $string22 = "Steal_Pipe_Token /PipeName" nocase ascii wide
                        $string23 = "Tokenvator" nocase ascii wide
                        $string24 = /Tokenvator.{0,1000}\.exe/ nocase ascii wide
                        $string25 = /Tokenvator\.csproj/ nocase ascii wide
                        $string26 = /Tokenvator\.exe/ nocase ascii wide
                        $string27 = /Tokenvator\.git/ nocase ascii wide
                        $string28 = /Tokenvator\.pdb/ nocase ascii wide
                        $string29 = /Tokenvator\.Plugins/ nocase ascii wide
                        $string30 = /Tokenvator\.Resources/ nocase ascii wide
                        $string31 = /Tokenvator\.sln/ nocase ascii wide
                        $string32 = "Tokenvator/MonkeyWorks" nocase ascii wide

    condition:
        any of them
}