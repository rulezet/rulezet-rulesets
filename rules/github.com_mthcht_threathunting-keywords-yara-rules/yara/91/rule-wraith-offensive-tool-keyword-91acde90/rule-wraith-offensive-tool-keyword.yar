rule rule_wraith_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wraith' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wraith"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wraith_offensive_tool_keyword = /\swraith\.py/ nocase ascii wide
                        $string2_wraith_offensive_tool_keyword = /\swraith\-server\.py/ nocase ascii wide
                        $string3_wraith_offensive_tool_keyword = /\swraith\-server_v.{0,1000}\.py/ nocase ascii wide
                        $string4_wraith_offensive_tool_keyword = "\"active_wraith_clients\"" nocase ascii wide
                        $string5_wraith_offensive_tool_keyword = "/assets/wraith-scripts/" nocase ascii wide
                        $string6_wraith_offensive_tool_keyword = /\/wraith\.git/ nocase ascii wide
                        $string7_wraith_offensive_tool_keyword = /\/wraith\.py/ nocase ascii wide
                        $string8_wraith_offensive_tool_keyword = /\/wraith\-master\.zip/ nocase ascii wide
                        $string9_wraith_offensive_tool_keyword = "/wraith-RAT-payloads" nocase ascii wide
                        $string10_wraith_offensive_tool_keyword = /\/wraith\-RAT\-payloads\.git/ nocase ascii wide
                        $string11_wraith_offensive_tool_keyword = /\/wraith\-server\.py/ nocase ascii wide
                        $string12_wraith_offensive_tool_keyword = /\/wraith\-server_v.{0,1000}\.py/ nocase ascii wide
                        $string13_wraith_offensive_tool_keyword = /\\wraith\.py/ nocase ascii wide
                        $string14_wraith_offensive_tool_keyword = /\\wraith\-master\.zip/ nocase ascii wide
                        $string15_wraith_offensive_tool_keyword = /\\wraith\-RAT\-payloads/ nocase ascii wide
                        $string16_wraith_offensive_tool_keyword = /\\wraith\-server\.py/ nocase ascii wide
                        $string17_wraith_offensive_tool_keyword = /\\wraith\-server_v.{0,1000}\.py/ nocase ascii wide
                        $string18_wraith_offensive_tool_keyword = "<h1>Wraith Login" nocase ascii wide
                        $string19_wraith_offensive_tool_keyword = "<title>Wraith Login</title>" nocase ascii wide
                        $string20_wraith_offensive_tool_keyword = "04eb0f500553c9d58de8f5a8bb102cba7dcb0d1e9a77baa4227237c49a5e81d8" nocase ascii wide
                        $string21_wraith_offensive_tool_keyword = "309c23d800972611948a5980921fdf6e78bdda2fc4d30f4dba3bd8c970a17e94" nocase ascii wide
                        $string22_wraith_offensive_tool_keyword = "76b70dcbcb1d45935f1b12eef38162b812f88bb4ff89a07a46609d879019103e" nocase ascii wide
                        $string23_wraith_offensive_tool_keyword = /dev\.l1qu1d\.net\/wraith\-labs\/wraith/ nocase ascii wide
                        $string24_wraith_offensive_tool_keyword = /login\.php\?LOGMEOUTPLZ\=true/ nocase ascii wide
                        $string25_wraith_offensive_tool_keyword = /script_main\(wraith\,\scmdline\)/ nocase ascii wide
                        $string26_wraith_offensive_tool_keyword = "Successfully installed wraith to run on startup " nocase ascii wide
                        $string27_wraith_offensive_tool_keyword = "TR-SLimey/wraith-RAT" nocase ascii wide
                        $string28_wraith_offensive_tool_keyword = "wraith-labs/wraith" nocase ascii wide

    condition:
        any of them
}