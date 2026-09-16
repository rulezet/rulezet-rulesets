rule EventLogMaster
{
    meta:
        description = "Detection patterns for the tool 'EventLogMaster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventLogMaster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sEventLogCredentials\.ps1/ nocase ascii wide
                        $string2 = /\sKillEvenlogService\.ps1/ nocase ascii wide
                        $string3 = /\/EventLogCredentials\.ps1/ nocase ascii wide
                        $string4 = /\/EventLogMaster\.git/ nocase ascii wide
                        $string5 = /\/KillEvenlogService\.ps1/ nocase ascii wide
                        $string6 = /\/RegfDenyTSConnections\.ps1/ nocase ascii wide
                        $string7 = /\\EventLogCredentials\.ps1/ nocase ascii wide
                        $string8 = /\\EventLogMaster\.cna/ nocase ascii wide
                        $string9 = /\\EventLogMaster\-master/ nocase ascii wide
                        $string10 = /\\KillEvenlogService\.ps1/ nocase ascii wide
                        $string11 = /\\RegfDenyTSConnections\.ps1/ nocase ascii wide
                        $string12 = "24690dc55d197a7a63bc2a80404a6e662c719e04bff38435796c666d1cfcb719" nocase ascii wide
                        $string13 = "30e270d972931c04fef43bb97b99a1d2f83cb87e26c65d2deb8c6e2fe4854630" nocase ascii wide
                        $string14 = "5e3d3d353d87bb0b41714922c72dc61f16d4bb3f20990ccb9be75b9689e864aa" nocase ascii wide
                        $string15 = "7a0abdd123fe8f650f37557666688ee7c050c94d8271462de50b5cb1e9b58246" nocase ascii wide
                        $string16 = "7afd2ebbf1c75880581e485fdd64d4b4cbb658a79cf271c0afa8092b8ce937ce" nocase ascii wide
                        $string17 = "7d6c67ce067fc1f459e617e2cb6d891e74ccdf3b4630fd64cb824b230a74dc8c" nocase ascii wide
                        $string18 = "c676b559a0d13fec22804c9489726a9a6ffbb6260c866cb5e5964067ea733bcc" nocase ascii wide
                        $string19 = /ClearnEventRecordID\.ps1/ nocase ascii wide
                        $string20 = /ClearnIpAddress\.ps1/ nocase ascii wide
                        $string21 = "QAX-A-Team/EventLogMaster" nocase ascii wide

    condition:
        any of them
}