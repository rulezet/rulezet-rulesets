rule rule_TunnelVision_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TunnelVision' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TunnelVision"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TunnelVision_offensive_tool_keyword = /\sconfigdhcpserver\.sh/ nocase ascii wide
                        $string2_TunnelVision_offensive_tool_keyword = /\sdhcpd\-noroute\.conf/ nocase ascii wide
                        $string3_TunnelVision_offensive_tool_keyword = /\snorouteconfig\.sh/ nocase ascii wide
                        $string4_TunnelVision_offensive_tool_keyword = /\sTunnelVisionVM\.ova/ nocase ascii wide
                        $string5_TunnelVision_offensive_tool_keyword = /\/configdhcpserver\.sh/ nocase ascii wide
                        $string6_TunnelVision_offensive_tool_keyword = /\/dhcpd\-noroute\.conf/
                        $string7_TunnelVision_offensive_tool_keyword = /\/norouteconfig\.sh/ nocase ascii wide
                        $string8_TunnelVision_offensive_tool_keyword = /\/TunnelVision\.git/ nocase ascii wide
                        $string9_TunnelVision_offensive_tool_keyword = /\/TunnelVisionVM\.ova/ nocase ascii wide
                        $string10_TunnelVision_offensive_tool_keyword = /\\TunnelVision\-main/ nocase ascii wide
                        $string11_TunnelVision_offensive_tool_keyword = /\\TunnelVisionVM\.ova/ nocase ascii wide
                        $string12_TunnelVision_offensive_tool_keyword = "354a7236afe220e7c831129fbf32434edd1d18961118dfb05279ff5c1b6f38ad" nocase ascii wide
                        $string13_TunnelVision_offensive_tool_keyword = "5176f4cdb10d1261d0327e76daf563a5dcc4e32b8556da761620bc1d467f002e" nocase ascii wide
                        $string14_TunnelVision_offensive_tool_keyword = "apt-get install isc-dhcp-server net-tools" nocase ascii wide
                        $string15_TunnelVision_offensive_tool_keyword = "d1b43d39823d14ec9524f63fa0125ad9606d5c3e32d8e10d34a25214c56d308f" nocase ascii wide
                        $string16_TunnelVision_offensive_tool_keyword = "d3fcbfcd8d9ca33ba19dffbcc8d5de2f8ef18baa028e41eded243a84d496e8d8" nocase ascii wide
                        $string17_TunnelVision_offensive_tool_keyword = "d987f5f570ddac113c3083de784aac66b7550f639fb0cdd6d88bed99ae21821c" nocase ascii wide
                        $string18_TunnelVision_offensive_tool_keyword = /https\:\/\/drive\.google\.com\/file\/d\/1WLJGs3ZUypf6hLh5WL4AJmsKdUOZo5yZ/ nocase ascii wide
                        $string19_TunnelVision_offensive_tool_keyword = "Installing DHCP server and net-tools" nocase ascii wide
                        $string20_TunnelVision_offensive_tool_keyword = /journalctl\s\-u\sisc\-dhcp\-server\.service\s\|\stail\s\-n\s50/ nocase ascii wide
                        $string21_TunnelVision_offensive_tool_keyword = "leviathansecurity/TunnelVision" nocase ascii wide
                        $string22_TunnelVision_offensive_tool_keyword = /Replacing\s\/etc\/dhcp\/dhcpd\.conf\swith\sno\sroute\spush\sconfig/
                        $string23_TunnelVision_offensive_tool_keyword = /sudo\s\.\/startup\.sh/
                        $string24_TunnelVision_offensive_tool_keyword = /TunnelVision\/pushrouteconfig\.sh/ nocase ascii wide
                        $string25_TunnelVision_offensive_tool_keyword = /www\.leviathansecurity\.com\/blog\/tunnelvision/ nocase ascii wide

    condition:
        any of them
}