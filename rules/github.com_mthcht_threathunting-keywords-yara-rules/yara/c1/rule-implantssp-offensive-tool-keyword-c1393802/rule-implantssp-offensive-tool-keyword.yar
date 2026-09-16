rule rule_ImplantSSP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ImplantSSP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ImplantSSP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ImplantSSP_offensive_tool_keyword = /\sImplantSSP\.exe/ nocase ascii wide
                        $string2_ImplantSSP_offensive_tool_keyword = /\/ImplantSSP\.exe/ nocase ascii wide
                        $string3_ImplantSSP_offensive_tool_keyword = /\[\+\]\sAdding\syour\sDLL\sto\sthe\sLSA\sSecurity\sPackages\sregistry\skey/ nocase ascii wide
                        $string4_ImplantSSP_offensive_tool_keyword = /\[\+\]\sRegistry\skey\sset\.\sDLL\swill\sbe\sloaded\son\sreboot/ nocase ascii wide
                        $string5_ImplantSSP_offensive_tool_keyword = /\[\+\]\sSafety\schecks\spassed\.\sImplanting\syour\sDLL/ nocase ascii wide
                        $string6_ImplantSSP_offensive_tool_keyword = /\\ImplantSSP\.exe/ nocase ascii wide
                        $string7_ImplantSSP_offensive_tool_keyword = /ImplantSSP\.csproj/ nocase ascii wide
                        $string8_ImplantSSP_offensive_tool_keyword = "master/ImplantSSP/" nocase ascii wide

    condition:
        any of them
}