rule Fynloski_Backdoor
{
    meta:
        description = "Detection patterns for the tool 'Fynloski Backdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fynloski Backdoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "#BOT#CloseServer" nocase ascii wide
                        $string2 = "#BOT#OpenUrl" nocase ascii wide
                        $string3 = "#BOT#RunPrompt" nocase ascii wide
                        $string4 = "#BOT#SvrUninstall" nocase ascii wide
                        $string5 = "#BOT#URLDownload" nocase ascii wide
                        $string6 = "#BOT#URLUpdate" nocase ascii wide
                        $string7 = "#GetClipboardText" nocase ascii wide
                        $string8 = "ActiveOfflineKeylogger" nocase ascii wide
                        $string9 = "ActiveOnlineKeylogger" nocase ascii wide
                        $string10 = "ActiveOnlineKeyStrokes" nocase ascii wide
                        $string11 = "ACTIVEREMOTESHELL" nocase ascii wide
                        $string12 = "DDOSHTTPFLOOD" nocase ascii wide
                        $string13 = "DDOSSYNFLOOD" nocase ascii wide
                        $string14 = "DDOSUDPFLOOD" nocase ascii wide
                        $string15 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!" nocase ascii wide
                        $string16 = "KILLREMOTESHELL" nocase ascii wide
                        $string17 = /ping\s127\.0\.0\.1\s\-n\s4\s\>\sNUL\s\&\&\s\\"/ nocase ascii wide

    condition:
        any of them
}