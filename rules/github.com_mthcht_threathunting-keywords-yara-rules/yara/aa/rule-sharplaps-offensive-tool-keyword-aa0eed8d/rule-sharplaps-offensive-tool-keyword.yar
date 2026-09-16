rule rule_SharpLAPS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpLAPS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpLAPS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpLAPS_offensive_tool_keyword = /\/SharpLAPS\.exe/ nocase ascii wide
                        $string2_SharpLAPS_offensive_tool_keyword = /\[\+\]\sExtracting\sLAPS\spassword\sfrom\sLDAP/ nocase ascii wide
                        $string3_SharpLAPS_offensive_tool_keyword = /\\SharpLAPS\.exe/ nocase ascii wide
                        $string4_SharpLAPS_offensive_tool_keyword = /\\SharpLAPS\.pdb/ nocase ascii wide
                        $string5_SharpLAPS_offensive_tool_keyword = ">SharpLAPS<" nocase ascii wide
                        $string6_SharpLAPS_offensive_tool_keyword = "1E0986B4-4BF3-4CEA-A885-347B6D232D46" nocase ascii wide
                        $string7_SharpLAPS_offensive_tool_keyword = "a0e17777243f0190053238f503971fc85321ffa8dc12b80bc50b93a2c0d3ea23" nocase ascii wide
                        $string8_SharpLAPS_offensive_tool_keyword = /SharpLAPS\.csproj/ nocase ascii wide
                        $string9_SharpLAPS_offensive_tool_keyword = /SharpLAPS\.exe/ nocase ascii wide
                        $string10_SharpLAPS_offensive_tool_keyword = /SharpLAPS\.sln/ nocase ascii wide
                        $string11_SharpLAPS_offensive_tool_keyword = "SharpLAPS-main" nocase ascii wide
                        $string12_SharpLAPS_offensive_tool_keyword = "swisskyrepo/SharpLAPS" nocase ascii wide

    condition:
        any of them
}