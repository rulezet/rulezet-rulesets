rule tacticalrmm
{
    meta:
        description = "Detection patterns for the tool 'tacticalrmm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tacticalrmm"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\srmm\-installer\.ps1/ nocase ascii wide
                        $string2 = /\stacticalrmm\.exe/ nocase ascii wide
                        $string3 = "/amidaware/rmmagent/releases/download/" nocase ascii wide
                        $string4 = /\/nats\-rmm\.conf/ nocase ascii wide
                        $string5 = "/rmm/api/tacticalrmm/" nocase ascii wide
                        $string6 = /\/rmm\-installer\.ps1/ nocase ascii wide
                        $string7 = /\/tacticalagent\.log/
                        $string8 = /\/tacticalagent\-v.{0,1000}\-.{0,1000}\.exe/ nocase ascii wide
                        $string9 = /\/tacticalagent\-v.{0,1000}\-linux\-arm\.exe/
                        $string10 = /\/tacticalagent\-v.{0,1000}\-windows\-amd64\.exe/ nocase ascii wide
                        $string11 = /\/tacticalrmm\.exe/ nocase ascii wide
                        $string12 = /\/tacticalrmm\.git/ nocase ascii wide
                        $string13 = /\/tacticalrmm\/master\/install\.sh/ nocase ascii wide
                        $string14 = "/tacticalrmm/releases/latest" nocase ascii wide
                        $string15 = /\/tacticalrmm\-web\.git/ nocase ascii wide
                        $string16 = /\\InventoryApplicationFile\\tacticalagent\-v2/ nocase ascii wide
                        $string17 = /\\Program\sFiles\\TacticalAgent\\/ nocase ascii wide
                        $string18 = /\\ProgramData\\TacticalRMM\\/ nocase ascii wide
                        $string19 = /\\rmm\-client\-site\-server\.exe/ nocase ascii wide
                        $string20 = /\\rmm\-client\-site\-server\.exe/ nocase ascii wide
                        $string21 = /\\rmm\-installer\.ps1/ nocase ascii wide
                        $string22 = /\\tacticalagent\-v.{0,1000}\-linux\-arm\.exe/ nocase ascii wide
                        $string23 = /\\tacticalagent\-v.{0,1000}\-windows\-amd64\.exe/ nocase ascii wide
                        $string24 = /\\tacticalrmm\.exe/ nocase ascii wide
                        $string25 = /\\tacticalrmm\\/ nocase ascii wide
                        $string26 = "amidaware/tacticalrmm" nocase ascii wide
                        $string27 = /https\:\/\/.{0,1000}\.tacticalrmm\.com\// nocase ascii wide
                        $string28 = "net stop tacticalrmm" nocase ascii wide
                        $string29 = /RMM\.WebRemote\.exe/ nocase ascii wide
                        $string30 = /SOFTWARE\\TacticalRMM/ nocase ascii wide
                        $string31 = "su - tactical" nocase ascii wide
                        $string32 = "sudo -s /bin/bash tactical"
                        $string33 = /systemctl\s.{0,1000}\srmm\.service/ nocase ascii wide
                        $string34 = "Tactical RMM Agent" nocase ascii wide
                        $string35 = /tacticalrmm\.utils/ nocase ascii wide
                        $string36 = "tacticalrmm-develop" nocase ascii wide

    condition:
        any of them
}