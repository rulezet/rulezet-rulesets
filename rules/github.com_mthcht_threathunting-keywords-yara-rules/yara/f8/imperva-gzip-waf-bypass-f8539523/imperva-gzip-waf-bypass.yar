rule Imperva_gzip_WAF_Bypass
{
    meta:
        description = "Detection patterns for the tool 'Imperva_gzip_WAF_Bypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Imperva_gzip_WAF_Bypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/Imperva_gzip_WAF_Bypass" nocase ascii wide
                        $string2 = /imperva_gzip\.py/ nocase ascii wide

    condition:
        any of them
}