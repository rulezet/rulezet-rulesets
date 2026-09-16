rule rule_xeox_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'xeox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xeox"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_xeox_greyware_tool_keyword = /\.xeox\.com/ nocase ascii wide
                        $string2_xeox_greyware_tool_keyword = /\\Temp\\XEOX/ nocase ascii wide
                        $string3_xeox_greyware_tool_keyword = /\\XEOX\\Agent\sWatchdog\son\sBoot/ nocase ascii wide
                        $string4_xeox_greyware_tool_keyword = /\\XEOX\\Agent\sWatchdog\son\sWakeup/ nocase ascii wide
                        $string5_xeox_greyware_tool_keyword = /\\XEOX\\Agent\sWatchdog/ nocase ascii wide
                        $string6_xeox_greyware_tool_keyword = /\\XEOX_cloud_agent_install\.bat/ nocase ascii wide
                        $string7_xeox_greyware_tool_keyword = /\\XEOXAgent\.exe/ nocase ascii wide
                        $string8_xeox_greyware_tool_keyword = /\\xeox\-agent_x64\\/ nocase ascii wide
                        $string9_xeox_greyware_tool_keyword = /agent01\.xeox\.com/ nocase ascii wide
                        $string10_xeox_greyware_tool_keyword = "echo Installing XEOX Agent" nocase ascii wide
                        $string11_xeox_greyware_tool_keyword = /https\:\/\/portal\.xeox\.com\// nocase ascii wide
                        $string12_xeox_greyware_tool_keyword = /ProgramFiles\(x86\)\\xeox\\/ nocase ascii wide
                        $string13_xeox_greyware_tool_keyword = /ProgramFiles\\xeox\\/ nocase ascii wide
                        $string14_xeox_greyware_tool_keyword = "ui/rest/download/xeoxagentgeneric/" nocase ascii wide
                        $string15_xeox_greyware_tool_keyword = "XEOX Agent for Windows" nocase ascii wide
                        $string16_xeox_greyware_tool_keyword = "XEOX Agent Service" nocase ascii wide
                        $string17_xeox_greyware_tool_keyword = /xeox\.com\/ui\/download\// nocase ascii wide
                        $string18_xeox_greyware_tool_keyword = /xeox_service_windows\.exe/ nocase ascii wide
                        $string19_xeox_greyware_tool_keyword = /xeox\-agent_.{0,1000}\.exe/ nocase ascii wide
                        $string20_xeox_greyware_tool_keyword = /xeox\-agent_x64\.exe/ nocase ascii wide
                        $string21_xeox_greyware_tool_keyword = /xeox\-agent_x86\.exe/ nocase ascii wide

    condition:
        any of them
}