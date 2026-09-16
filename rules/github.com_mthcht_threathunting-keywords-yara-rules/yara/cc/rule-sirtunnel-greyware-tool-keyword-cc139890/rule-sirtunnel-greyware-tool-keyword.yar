rule rule_SirTunnel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SirTunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SirTunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_SirTunnel_greyware_tool_keyword = /\s\$domain\ssirtunnel\s\$domain\s\$serverPort/ nocase ascii wide
                        $string2_SirTunnel_greyware_tool_keyword = /\ssirtunnel\.py/ nocase ascii wide
                        $string3_SirTunnel_greyware_tool_keyword = "/config/apps/http/servers/sirtunnel/routes" nocase ascii wide
                        $string4_SirTunnel_greyware_tool_keyword = /\/SirTunnel\.git/ nocase ascii wide
                        $string5_SirTunnel_greyware_tool_keyword = /\/sirtunnel\.py/ nocase ascii wide
                        $string6_SirTunnel_greyware_tool_keyword = /\\sirtunnel\.py/ nocase ascii wide
                        $string7_SirTunnel_greyware_tool_keyword = "anderspitman/SirTunnel" nocase ascii wide
                        $string8_SirTunnel_greyware_tool_keyword = "d5687d84d518119cbdd84183bfe8cb29009d054794b3aed5bda7ad117a7e4d5e" nocase ascii wide
                        $string9_SirTunnel_greyware_tool_keyword = "daps94/SirTunnel" nocase ascii wide
                        $string10_SirTunnel_greyware_tool_keyword = /http\:\/\/127\.0\.0\.1\:2019\/id\// nocase ascii wide
                        $string11_SirTunnel_greyware_tool_keyword = "matiboy/SirTunnel" nocase ascii wide

    condition:
        any of them
}