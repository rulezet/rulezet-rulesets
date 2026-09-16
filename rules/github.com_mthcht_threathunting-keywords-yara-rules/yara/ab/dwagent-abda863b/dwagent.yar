rule dwagent
{
    meta:
        description = "Detection patterns for the tool 'dwagent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dwagent"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/dwagent\.desktop/
                        $string2 = /\/dwagent\.service/
                        $string3 = "/dwagsystray"
                        $string4 = /\\\.dwagent\\/ nocase ascii wide
                        $string5 = /\\AppData\\Local\\Temp\\dwagent/ nocase ascii wide
                        $string6 = /\\CurrentVersion\\Run\\DWAgentMon/ nocase ascii wide
                        $string7 = /\\dwagent\.exe/ nocase ascii wide
                        $string8 = /\\DWAgent\.lnk/ nocase ascii wide
                        $string9 = /\\dwagent\.log/ nocase ascii wide
                        $string10 = /\\dwagent\.pid/ nocase ascii wide
                        $string11 = /\\dwagent\.start/ nocase ascii wide
                        $string12 = /\\dwagent\.stop/ nocase ascii wide
                        $string13 = /\\dwaggdi\.dll/ nocase ascii wide
                        $string14 = /\\dwaginstall\.log/ nocase ascii wide
                        $string15 = /\\dwaglnc\.exe/ nocase ascii wide
                        $string16 = /\\dwagsvc\.exe/ nocase ascii wide
                        $string17 = /\\dwagupd\.dll/ nocase ascii wide
                        $string18 = /\\Services\\DWAgent/ nocase ascii wide
                        $string19 = /\\Start\sMenu\\Programs\\DWAgent/ nocase ascii wide
                        $string20 = ">DWAgent<" nocase ascii wide
                        $string21 = "015774ac49fa929ca39c0707aa8177e4605b7df9f53d8630fea1ef5155bb5328" nocase ascii wide
                        $string22 = "1429e62855ce5572b735fe0460ffa6a8f26d56199a8e166152252c7bd659d275" nocase ascii wide
                        $string23 = "3241d780f32a6a89d3b3f30d85f21f33f9d4d91227d129b2fd81d75baa870337" nocase ascii wide
                        $string24 = "36a7532a957652a55dbf0b196905652a1f0b8c4019b7ca4e749fa81e5f2c149b" nocase ascii wide
                        $string25 = "4f21a1d0e7caa97018e4d0b8c7e63fbc54d081976dfda9409f57a3ead24074a7" nocase ascii wide
                        $string26 = "cd12e8a285c77102487f04726b91bc649f9ad087a1e9a5546124a0cc7480c221" nocase ascii wide
                        $string27 = "d2b2455b755476d0b35c721ccdb84432e51812ab646a9210137c1e85b90d7de4" nocase ascii wide
                        $string28 = /dwagent_install\.log/ nocase ascii wide
                        $string29 = /dwagent_unistall\.log/ nocase ascii wide
                        $string30 = /dwaggdi_x86_32\.dll/ nocase ascii wide
                        $string31 = /dwaggdi_x86_64\.dll/ nocase ascii wide
                        $string32 = /dwagscreencapture\.dll/ nocase ascii wide
                        $string33 = /dwagscreencapturebitblt\.dll/ nocase ascii wide
                        $string34 = /dwagscreencapturedesktopduplication\.dll/ nocase ascii wide
                        $string35 = "dwservice/agent" nocase ascii wide
                        $string36 = /Program\sFiles\\DWAgent/ nocase ascii wide
                        $string37 = /www\.dwservice\.net/ nocase ascii wide

    condition:
        any of them
}