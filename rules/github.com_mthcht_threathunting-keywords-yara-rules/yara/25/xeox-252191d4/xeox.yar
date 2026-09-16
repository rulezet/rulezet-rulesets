rule xeox
{
    meta:
        description = "Detection patterns for the tool 'xeox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xeox"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.xeox\.com/ nocase ascii wide
                        $string2 = /\\Temp\\XEOX/ nocase ascii wide
                        $string3 = /\\XEOX\\Agent\sWatchdog\son\sBoot/ nocase ascii wide
                        $string4 = /\\XEOX\\Agent\sWatchdog\son\sWakeup/ nocase ascii wide
                        $string5 = /\\XEOX\\Agent\sWatchdog/ nocase ascii wide
                        $string6 = /\\XEOX_cloud_agent_install\.bat/ nocase ascii wide
                        $string7 = /\\XEOXAgent\.exe/ nocase ascii wide
                        $string8 = /\\xeox\-agent_x64\\/ nocase ascii wide
                        $string9 = /agent01\.xeox\.com/ nocase ascii wide
                        $string10 = "echo Installing XEOX Agent" nocase ascii wide
                        $string11 = /https\:\/\/portal\.xeox\.com\// nocase ascii wide
                        $string12 = /ProgramFiles\(x86\)\\xeox\\/ nocase ascii wide
                        $string13 = /ProgramFiles\\xeox\\/ nocase ascii wide
                        $string14 = "ui/rest/download/xeoxagentgeneric/" nocase ascii wide
                        $string15 = "XEOX Agent for Windows" nocase ascii wide
                        $string16 = "XEOX Agent Service" nocase ascii wide
                        $string17 = /xeox\.com\/ui\/download\// nocase ascii wide
                        $string18 = /xeox_service_windows\.exe/ nocase ascii wide
                        $string19 = /xeox\-agent_.{0,1000}\.exe/ nocase ascii wide
                        $string20 = /xeox\-agent_x64\.exe/ nocase ascii wide
                        $string21 = /xeox\-agent_x86\.exe/ nocase ascii wide

    condition:
        any of them
}