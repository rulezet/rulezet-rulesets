rule SirTunnel
{
    meta:
        description = "Detection patterns for the tool 'SirTunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SirTunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\$domain\ssirtunnel\s\$domain\s\$serverPort/ nocase ascii wide
                        $string2 = /\ssirtunnel\.py/ nocase ascii wide
                        $string3 = "/config/apps/http/servers/sirtunnel/routes" nocase ascii wide
                        $string4 = /\/SirTunnel\.git/ nocase ascii wide
                        $string5 = /\/sirtunnel\.py/ nocase ascii wide
                        $string6 = /\\sirtunnel\.py/ nocase ascii wide
                        $string7 = "anderspitman/SirTunnel" nocase ascii wide
                        $string8 = "d5687d84d518119cbdd84183bfe8cb29009d054794b3aed5bda7ad117a7e4d5e" nocase ascii wide
                        $string9 = "daps94/SirTunnel" nocase ascii wide
                        $string10 = /http\:\/\/127\.0\.0\.1\:2019\/id\// nocase ascii wide
                        $string11 = "matiboy/SirTunnel" nocase ascii wide

    condition:
        any of them
}