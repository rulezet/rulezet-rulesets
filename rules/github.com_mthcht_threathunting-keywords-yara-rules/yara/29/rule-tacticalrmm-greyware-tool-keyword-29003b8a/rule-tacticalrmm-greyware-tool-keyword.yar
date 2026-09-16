rule rule_tacticalrmm_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tacticalrmm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tacticalrmm"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tacticalrmm_greyware_tool_keyword = /\srmm\-installer\.ps1/ nocase ascii wide
                        $string2_tacticalrmm_greyware_tool_keyword = /\stacticalrmm\.exe/ nocase ascii wide
                        $string3_tacticalrmm_greyware_tool_keyword = "/amidaware/rmmagent/releases/download/" nocase ascii wide
                        $string4_tacticalrmm_greyware_tool_keyword = /\/nats\-rmm\.conf/ nocase ascii wide
                        $string5_tacticalrmm_greyware_tool_keyword = "/rmm/api/tacticalrmm/" nocase ascii wide
                        $string6_tacticalrmm_greyware_tool_keyword = /\/rmm\-installer\.ps1/ nocase ascii wide
                        $string7_tacticalrmm_greyware_tool_keyword = /\/tacticalagent\.log/
                        $string8_tacticalrmm_greyware_tool_keyword = /\/tacticalagent\-v.{0,1000}\-.{0,1000}\.exe/ nocase ascii wide
                        $string9_tacticalrmm_greyware_tool_keyword = /\/tacticalagent\-v.{0,1000}\-linux\-arm\.exe/
                        $string10_tacticalrmm_greyware_tool_keyword = /\/tacticalagent\-v.{0,1000}\-windows\-amd64\.exe/ nocase ascii wide
                        $string11_tacticalrmm_greyware_tool_keyword = /\/tacticalrmm\.exe/ nocase ascii wide
                        $string12_tacticalrmm_greyware_tool_keyword = /\/tacticalrmm\.git/ nocase ascii wide
                        $string13_tacticalrmm_greyware_tool_keyword = /\/tacticalrmm\/master\/install\.sh/ nocase ascii wide
                        $string14_tacticalrmm_greyware_tool_keyword = "/tacticalrmm/releases/latest" nocase ascii wide
                        $string15_tacticalrmm_greyware_tool_keyword = /\/tacticalrmm\-web\.git/ nocase ascii wide
                        $string16_tacticalrmm_greyware_tool_keyword = /\\InventoryApplicationFile\\tacticalagent\-v2/ nocase ascii wide
                        $string17_tacticalrmm_greyware_tool_keyword = /\\Program\sFiles\\TacticalAgent\\/ nocase ascii wide
                        $string18_tacticalrmm_greyware_tool_keyword = /\\ProgramData\\TacticalRMM\\/ nocase ascii wide
                        $string19_tacticalrmm_greyware_tool_keyword = /\\rmm\-client\-site\-server\.exe/ nocase ascii wide
                        $string20_tacticalrmm_greyware_tool_keyword = /\\rmm\-client\-site\-server\.exe/ nocase ascii wide
                        $string21_tacticalrmm_greyware_tool_keyword = /\\rmm\-installer\.ps1/ nocase ascii wide
                        $string22_tacticalrmm_greyware_tool_keyword = /\\tacticalagent\-v.{0,1000}\-linux\-arm\.exe/ nocase ascii wide
                        $string23_tacticalrmm_greyware_tool_keyword = /\\tacticalagent\-v.{0,1000}\-windows\-amd64\.exe/ nocase ascii wide
                        $string24_tacticalrmm_greyware_tool_keyword = /\\tacticalrmm\.exe/ nocase ascii wide
                        $string25_tacticalrmm_greyware_tool_keyword = /\\tacticalrmm\\/ nocase ascii wide
                        $string26_tacticalrmm_greyware_tool_keyword = "amidaware/tacticalrmm" nocase ascii wide
                        $string27_tacticalrmm_greyware_tool_keyword = /https\:\/\/.{0,1000}\.tacticalrmm\.com\// nocase ascii wide
                        $string28_tacticalrmm_greyware_tool_keyword = "net stop tacticalrmm" nocase ascii wide
                        $string29_tacticalrmm_greyware_tool_keyword = /RMM\.WebRemote\.exe/ nocase ascii wide
                        $string30_tacticalrmm_greyware_tool_keyword = /SOFTWARE\\TacticalRMM/ nocase ascii wide
                        $string31_tacticalrmm_greyware_tool_keyword = "su - tactical" nocase ascii wide
                        $string32_tacticalrmm_greyware_tool_keyword = "sudo -s /bin/bash tactical"
                        $string33_tacticalrmm_greyware_tool_keyword = /systemctl\s.{0,1000}\srmm\.service/ nocase ascii wide
                        $string34_tacticalrmm_greyware_tool_keyword = "Tactical RMM Agent" nocase ascii wide
                        $string35_tacticalrmm_greyware_tool_keyword = /tacticalrmm\.utils/ nocase ascii wide
                        $string36_tacticalrmm_greyware_tool_keyword = "tacticalrmm-develop" nocase ascii wide

    condition:
        any of them
}