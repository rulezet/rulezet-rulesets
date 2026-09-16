rule shootback
{
    meta:
        description = "Detection patterns for the tool 'shootback' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shootback"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "aploium/shootback" nocase ascii wide
                        $string2 = "bd582dca867f580de4cea00df8dafe985f7790233de90f7e962b6e6a80dd55cf" nocase ascii wide
                        $string3 = "dd7677e9132c0e2b813bf5a5fd4b34772d0804cf36b7266a2b9d0e64075019d0" nocase ascii wide
                        $string4 = /python3\sslaver\.py\s/ nocase ascii wide
                        $string5 = /shadowsocks_server.{0,1000}shootback_slaver/ nocase ascii wide

    condition:
        any of them
}