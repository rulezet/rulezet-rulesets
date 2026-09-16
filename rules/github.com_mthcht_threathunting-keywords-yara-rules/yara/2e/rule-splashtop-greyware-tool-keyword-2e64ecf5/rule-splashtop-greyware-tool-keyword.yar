rule rule_Splashtop_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Splashtop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Splashtop"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Splashtop_greyware_tool_keyword = /\.api\.splashtop\.com/ nocase ascii wide
                        $string2_Splashtop_greyware_tool_keyword = /\.relay\.splashtop\.com/ nocase ascii wide
                        $string3_Splashtop_greyware_tool_keyword = /\/Library\/Logs\/SPLog\.txt/
                        $string4_Splashtop_greyware_tool_keyword = /\/SplashtopStreamer\/SPLog\.txt/
                        $string5_Splashtop_greyware_tool_keyword = /\\slave\\workspace\\GIT_WIN_SRS_Formal\\Source\\irisserver\\/ nocase ascii wide
                        $string6_Splashtop_greyware_tool_keyword = /\\Splashtop\sRemote\\/ nocase ascii wide
                        $string7_Splashtop_greyware_tool_keyword = /\\Splashtop\\Temp\\/ nocase ascii wide
                        $string8_Splashtop_greyware_tool_keyword = /\\Splashtop\\Temp\\log\\FTCLog\.txt/ nocase ascii wide
                        $string9_Splashtop_greyware_tool_keyword = /\\SRService\.exe/ nocase ascii wide
                        $string10_Splashtop_greyware_tool_keyword = /\\strwinclt\.exe/ nocase ascii wide
                        $string11_Splashtop_greyware_tool_keyword = /\\WOW6432Node\\Splashtop\sInc\.\\Splashtop\sRemote\sServer/ nocase ascii wide
                        $string12_Splashtop_greyware_tool_keyword = /CurrentVersion\\Uninstall\\Splashtop\sInc\.\\/ nocase ascii wide
                        $string13_Splashtop_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Splashtop/ nocase ascii wide
                        $string14_Splashtop_greyware_tool_keyword = /Software\\Splashtop\sInc\.\\Splashtop/ nocase ascii wide
                        $string15_Splashtop_greyware_tool_keyword = /Splashtop\sRemote\\Server\\log\\agent_log\.txt/ nocase ascii wide
                        $string16_Splashtop_greyware_tool_keyword = /Splashtop\sRemote\\Server\\log\\SPLog\.txt/ nocase ascii wide
                        $string17_Splashtop_greyware_tool_keyword = /Splashtop\sRemote\\Server\\log\\svcinfo\.txt/ nocase ascii wide
                        $string18_Splashtop_greyware_tool_keyword = /Splashtop\sRemote\\Server\\log\\sysinfo\.txt/ nocase ascii wide
                        $string19_Splashtop_greyware_tool_keyword = /Splashtop_Streamer_Windows_.{0,1000}\.exe/ nocase ascii wide
                        $string20_Splashtop_greyware_tool_keyword = "Splashtop-Splashtop Streamer-" nocase ascii wide
                        $string21_Splashtop_greyware_tool_keyword = /SplashtopStreamer\..{0,1000}\.exe/ nocase ascii wide
                        $string22_Splashtop_greyware_tool_keyword = /SplashtopStreamer3500\.exe.{0,1000}\sprevercheck\s/ nocase ascii wide
                        $string23_Splashtop_greyware_tool_keyword = /www\.splashtop\.com\/remotecaRemoveVRootsISCHECKFORPRODUCTUPDATES/ nocase ascii wide

    condition:
        any of them
}