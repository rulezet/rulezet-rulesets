rule Splashtop
{
    meta:
        description = "Detection patterns for the tool 'Splashtop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Splashtop"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.api\.splashtop\.com/ nocase ascii wide
                        $string2 = /\.relay\.splashtop\.com/ nocase ascii wide
                        $string3 = /\/Library\/Logs\/SPLog\.txt/
                        $string4 = /\/SplashtopStreamer\/SPLog\.txt/
                        $string5 = /\\slave\\workspace\\GIT_WIN_SRS_Formal\\Source\\irisserver\\/ nocase ascii wide
                        $string6 = /\\Splashtop\sRemote\\/ nocase ascii wide
                        $string7 = /\\Splashtop\\Temp\\/ nocase ascii wide
                        $string8 = /\\Splashtop\\Temp\\log\\FTCLog\.txt/ nocase ascii wide
                        $string9 = /\\SRService\.exe/ nocase ascii wide
                        $string10 = /\\strwinclt\.exe/ nocase ascii wide
                        $string11 = /\\WOW6432Node\\Splashtop\sInc\.\\Splashtop\sRemote\sServer/ nocase ascii wide
                        $string12 = /CurrentVersion\\Uninstall\\Splashtop\sInc\.\\/ nocase ascii wide
                        $string13 = /Program\sFiles\s\(x86\)\\Splashtop/ nocase ascii wide
                        $string14 = /Software\\Splashtop\sInc\.\\Splashtop/ nocase ascii wide
                        $string15 = /Splashtop\sRemote\\Server\\log\\agent_log\.txt/ nocase ascii wide
                        $string16 = /Splashtop\sRemote\\Server\\log\\SPLog\.txt/ nocase ascii wide
                        $string17 = /Splashtop\sRemote\\Server\\log\\svcinfo\.txt/ nocase ascii wide
                        $string18 = /Splashtop\sRemote\\Server\\log\\sysinfo\.txt/ nocase ascii wide
                        $string19 = /Splashtop_Streamer_Windows_.{0,1000}\.exe/ nocase ascii wide
                        $string20 = "Splashtop-Splashtop Streamer-" nocase ascii wide
                        $string21 = /SplashtopStreamer\..{0,1000}\.exe/ nocase ascii wide
                        $string22 = /SplashtopStreamer3500\.exe.{0,1000}\sprevercheck\s/ nocase ascii wide
                        $string23 = /www\.splashtop\.com\/remotecaRemoveVRootsISCHECKFORPRODUCTUPDATES/ nocase ascii wide

    condition:
        any of them
}