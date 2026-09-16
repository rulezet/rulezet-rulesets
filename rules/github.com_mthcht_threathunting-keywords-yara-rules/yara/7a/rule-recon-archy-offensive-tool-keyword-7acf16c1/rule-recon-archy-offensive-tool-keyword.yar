rule rule_recon_archy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'recon-archy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "recon-archy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_recon_archy_offensive_tool_keyword = /\/recon\-archy\.git/ nocase ascii wide
                        $string2_recon_archy_offensive_tool_keyword = "recon-archy analyse" nocase ascii wide
                        $string3_recon_archy_offensive_tool_keyword = "recon-archy build" nocase ascii wide
                        $string4_recon_archy_offensive_tool_keyword = "recon-archy crawl" nocase ascii wide
                        $string5_recon_archy_offensive_tool_keyword = "recon-archy-master" nocase ascii wide
                        $string6_recon_archy_offensive_tool_keyword = "remiflavien1/recon-archy" nocase ascii wide
                        $string7_recon_archy_offensive_tool_keyword = "shadawck/recon-archy" nocase ascii wide

    condition:
        any of them
}