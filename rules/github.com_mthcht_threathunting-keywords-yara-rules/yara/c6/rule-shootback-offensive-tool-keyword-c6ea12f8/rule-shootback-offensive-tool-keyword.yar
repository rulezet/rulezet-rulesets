rule rule_shootback_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'shootback' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shootback"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_shootback_offensive_tool_keyword = "aploium/shootback" nocase ascii wide
                        $string2_shootback_offensive_tool_keyword = "bd582dca867f580de4cea00df8dafe985f7790233de90f7e962b6e6a80dd55cf" nocase ascii wide
                        $string3_shootback_offensive_tool_keyword = "dd7677e9132c0e2b813bf5a5fd4b34772d0804cf36b7266a2b9d0e64075019d0" nocase ascii wide
                        $string4_shootback_offensive_tool_keyword = /python3\sslaver\.py\s/ nocase ascii wide
                        $string5_shootback_offensive_tool_keyword = /shadowsocks_server.{0,1000}shootback_slaver/ nocase ascii wide

    condition:
        any of them
}