rule rule_htran_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'htran' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "htran"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_htran_offensive_tool_keyword = /\sCode\sby\slion\s\&\sbkbll\,\sWelcome\sto\shttp\:\/\/www\.cnhonker\.com\s/ nocase ascii wide
                        $string2_htran_offensive_tool_keyword = " -tran <ConnectPort> <TransmitHost> <TransmitPort>" nocase ascii wide
                        $string3_htran_offensive_tool_keyword = "/bin/htran"
                        $string4_htran_offensive_tool_keyword = /\/htran\.exe/ nocase ascii wide
                        $string5_htran_offensive_tool_keyword = /\/HTran\.git/ nocase ascii wide
                        $string6_htran_offensive_tool_keyword = /\/Htran\-master\.zip/ nocase ascii wide
                        $string7_htran_offensive_tool_keyword = /\[\+\]\sOK\!\sI\sClosed\sThe\sTwo\sSocket\./ nocase ascii wide
                        $string8_htran_offensive_tool_keyword = /\\htran\.exe/ nocase ascii wide
                        $string9_htran_offensive_tool_keyword = /\\Htran\-master\.zip/ nocase ascii wide
                        $string10_htran_offensive_tool_keyword = "= HUC Packet Transmit Tool V" nocase ascii wide
                        $string11_htran_offensive_tool_keyword = "======================== htran V%s =======================" nocase ascii wide
                        $string12_htran_offensive_tool_keyword = "23092e288c27221ba793178e177a04309cf5c6073e2a022f5c4035252d69086d" nocase ascii wide
                        $string13_htran_offensive_tool_keyword = "b54ab14a7ad0460c7ac6416a9ad01e7015d32573571114b569f4769a2eb12e70" nocase ascii wide
                        $string14_htran_offensive_tool_keyword = "e5aef5ed2d977915b2288135ea8689b1fb15f619021a8a5b788a475a068cde8b" nocase ascii wide
                        $string15_htran_offensive_tool_keyword = "HiwinCN/Htran" nocase ascii wide
                        $string16_htran_offensive_tool_keyword = /HTran\.cpp\s\-\sHUC\sPacket\sTransmit\sTool\./ nocase ascii wide
                        $string17_htran_offensive_tool_keyword = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" nocase ascii wide

    condition:
        any of them
}