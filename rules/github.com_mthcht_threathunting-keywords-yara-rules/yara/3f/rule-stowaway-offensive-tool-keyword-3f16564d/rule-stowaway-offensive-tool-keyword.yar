rule rule_stowaway_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'stowaway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stowaway"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_stowaway_offensive_tool_keyword = " Author:ph4ntom" nocase ascii wide
                        $string2_stowaway_offensive_tool_keyword = /\s\-c\s.{0,1000}\s\-s\s.{0,1000}\s\-\-proxy\s.{0,1000}\s\-\-proxyu\s.{0,1000}\s\-\-proxyp\s.{0,1000}\s\-\-reconnect\s/ nocase ascii wide
                        $string3_stowaway_offensive_tool_keyword = /\sProxyStream\s.{0,1000}Stowaway/ nocase ascii wide
                        $string4_stowaway_offensive_tool_keyword = /\/script\/reuse\.py/
                        $string5_stowaway_offensive_tool_keyword = /\/Stowaway\.git/ nocase ascii wide
                        $string6_stowaway_offensive_tool_keyword = "/stowaway_admin"
                        $string7_stowaway_offensive_tool_keyword = "/stowaway_agent"
                        $string8_stowaway_offensive_tool_keyword = /\/windows_x64_admin\.exe/ nocase ascii wide
                        $string9_stowaway_offensive_tool_keyword = /\/windows_x64_agent\.exe/ nocase ascii wide
                        $string10_stowaway_offensive_tool_keyword = /\/windows_x86_admin\.exe/ nocase ascii wide
                        $string11_stowaway_offensive_tool_keyword = /\/windows_x86_agent\.exe/ nocase ascii wide
                        $string12_stowaway_offensive_tool_keyword = /\\mipsel_agent/ nocase ascii wide
                        $string13_stowaway_offensive_tool_keyword = /\\Stowaway\\admin\\/ nocase ascii wide
                        $string14_stowaway_offensive_tool_keyword = /\\Stowaway\\agent\\/ nocase ascii wide
                        $string15_stowaway_offensive_tool_keyword = /\\Stowaway\\ansicon\\/ nocase ascii wide
                        $string16_stowaway_offensive_tool_keyword = /\\windows_x64_admin\.exe/ nocase ascii wide
                        $string17_stowaway_offensive_tool_keyword = /\\windows_x64_agent\.exe/ nocase ascii wide
                        $string18_stowaway_offensive_tool_keyword = /\\windows_x86_admin\.exe/ nocase ascii wide
                        $string19_stowaway_offensive_tool_keyword = /\\windows_x86_agent\.exe/ nocase ascii wide
                        $string20_stowaway_offensive_tool_keyword = /\]\sStarting\sagent\snode\sactively\.Connecting\sto\s.{0,1000}Reconnecting\severy\s.{0,1000}\sseconds/ nocase ascii wide
                        $string21_stowaway_offensive_tool_keyword = "1df8bc4fb468ccc0fd85b553411d9b3eb7a2ba4c4a4469ae41913eef9a9e65f6" nocase ascii wide
                        $string22_stowaway_offensive_tool_keyword = "a78d737f30e03d166d4e3e3b2dca71d54f1cbf582206dfe16a1e717ce3dc0ef7" nocase ascii wide
                        $string23_stowaway_offensive_tool_keyword = "ac9215db682509ab2bdcba7fe924d84dafa1d8aade87172c1c6328b2cb6c9e52" nocase ascii wide
                        $string24_stowaway_offensive_tool_keyword = /linux_x64_agent\s\-\-report\s.{0,1000}\s\-l\s.{0,1000}\s\-s\sph4ntom/
                        $string25_stowaway_offensive_tool_keyword = "ph4ntonn/Stowaway" nocase ascii wide
                        $string26_stowaway_offensive_tool_keyword = /python\sreuse\.py\s\-\-start\s\-\-rhost\s.{0,1000}\s\-\-rport\s/ nocase ascii wide
                        $string27_stowaway_offensive_tool_keyword = "release/mipsel_agent" nocase ascii wide
                        $string28_stowaway_offensive_tool_keyword = "--socks5-proxy socks5" nocase ascii wide
                        $string29_stowaway_offensive_tool_keyword = "--socks5-proxyp socks5" nocase ascii wide
                        $string30_stowaway_offensive_tool_keyword = "--socks5-proxyu socks5" nocase ascii wide
                        $string31_stowaway_offensive_tool_keyword = "'start/stop iptables port reuse'" nocase ascii wide
                        $string32_stowaway_offensive_tool_keyword = "Stowaway/admin/process" nocase ascii wide

    condition:
        any of them
}