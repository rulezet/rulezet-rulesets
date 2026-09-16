rule rule_rattler_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rattler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rattler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rattler_offensive_tool_keyword = /\sRattler\.exe/ nocase ascii wide
                        $string2_rattler_offensive_tool_keyword = /\sRattler_32\.exe/ nocase ascii wide
                        $string3_rattler_offensive_tool_keyword = /\sRattler_x64\.exe/ nocase ascii wide
                        $string4_rattler_offensive_tool_keyword = /\/download\/v1\.0\/payload\.dll/ nocase ascii wide
                        $string5_rattler_offensive_tool_keyword = /\/rattler\.git/ nocase ascii wide
                        $string6_rattler_offensive_tool_keyword = /\/Rattler_32\.exe/ nocase ascii wide
                        $string7_rattler_offensive_tool_keyword = /\/Rattler_x64\.exe/ nocase ascii wide
                        $string8_rattler_offensive_tool_keyword = /\\rattler\.cpp/ nocase ascii wide
                        $string9_rattler_offensive_tool_keyword = /\\Rattler\.exe/ nocase ascii wide
                        $string10_rattler_offensive_tool_keyword = /\\Rattler_32\.exe/ nocase ascii wide
                        $string11_rattler_offensive_tool_keyword = /\\Rattler_x64\.exe/ nocase ascii wide
                        $string12_rattler_offensive_tool_keyword = /\\rattler\-master/ nocase ascii wide
                        $string13_rattler_offensive_tool_keyword = /\]\sINFO\:\sDLL\sIS\sVULNERABLE\sTO\sDOWNLOADS\sINSTALLER\sTEST\-/ nocase ascii wide
                        $string14_rattler_offensive_tool_keyword = /\]\sINFO\:\sDLL\sIS\sVULNERABLE\sTO\sEXECUTABLE\sTEST/ nocase ascii wide
                        $string15_rattler_offensive_tool_keyword = /\]\sTARGET\sDLL\sIS\sNOT\sVULNERABLE\sTO\s/ nocase ascii wide
                        $string16_rattler_offensive_tool_keyword = "0de61f6d712f44fd8337794c3d933d3e0de24bae9235383904541997c604b47a" nocase ascii wide
                        $string17_rattler_offensive_tool_keyword = "2d00a5df9000f49c0b42ca0fe316103af9cc3bdf11bea4da5255690193d3ef21" nocase ascii wide
                        $string18_rattler_offensive_tool_keyword = "3df5882d88914a064cbba240e1b3615c69c432f807f949a80d0d4b5a9f44ef77" nocase ascii wide
                        $string19_rattler_offensive_tool_keyword = "cea27c53085b6cf1d9505957144aa23b794550da5746e6a38a212a03b505e157" nocase ascii wide
                        $string20_rattler_offensive_tool_keyword = "sensepost/rattler" nocase ascii wide

    condition:
        any of them
}