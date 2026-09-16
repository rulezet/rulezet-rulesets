rule wraith
{
    meta:
        description = "Detection patterns for the tool 'wraith' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wraith"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\swraith\.py/ nocase ascii wide
                        $string2 = /\swraith\-server\.py/ nocase ascii wide
                        $string3 = /\swraith\-server_v.{0,1000}\.py/ nocase ascii wide
                        $string4 = "\"active_wraith_clients\"" nocase ascii wide
                        $string5 = "/assets/wraith-scripts/" nocase ascii wide
                        $string6 = /\/wraith\.git/ nocase ascii wide
                        $string7 = /\/wraith\.py/ nocase ascii wide
                        $string8 = /\/wraith\-master\.zip/ nocase ascii wide
                        $string9 = "/wraith-RAT-payloads" nocase ascii wide
                        $string10 = /\/wraith\-RAT\-payloads\.git/ nocase ascii wide
                        $string11 = /\/wraith\-server\.py/ nocase ascii wide
                        $string12 = /\/wraith\-server_v.{0,1000}\.py/ nocase ascii wide
                        $string13 = /\\wraith\.py/ nocase ascii wide
                        $string14 = /\\wraith\-master\.zip/ nocase ascii wide
                        $string15 = /\\wraith\-RAT\-payloads/ nocase ascii wide
                        $string16 = /\\wraith\-server\.py/ nocase ascii wide
                        $string17 = /\\wraith\-server_v.{0,1000}\.py/ nocase ascii wide
                        $string18 = "<h1>Wraith Login" nocase ascii wide
                        $string19 = "<title>Wraith Login</title>" nocase ascii wide
                        $string20 = "04eb0f500553c9d58de8f5a8bb102cba7dcb0d1e9a77baa4227237c49a5e81d8" nocase ascii wide
                        $string21 = "309c23d800972611948a5980921fdf6e78bdda2fc4d30f4dba3bd8c970a17e94" nocase ascii wide
                        $string22 = "76b70dcbcb1d45935f1b12eef38162b812f88bb4ff89a07a46609d879019103e" nocase ascii wide
                        $string23 = /dev\.l1qu1d\.net\/wraith\-labs\/wraith/ nocase ascii wide
                        $string24 = /login\.php\?LOGMEOUTPLZ\=true/ nocase ascii wide
                        $string25 = /script_main\(wraith\,\scmdline\)/ nocase ascii wide
                        $string26 = "Successfully installed wraith to run on startup " nocase ascii wide
                        $string27 = "TR-SLimey/wraith-RAT" nocase ascii wide
                        $string28 = "wraith-labs/wraith" nocase ascii wide

    condition:
        any of them
}