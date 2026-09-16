rule ImplantSSP
{
    meta:
        description = "Detection patterns for the tool 'ImplantSSP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ImplantSSP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sImplantSSP\.exe/ nocase ascii wide
                        $string2 = /\/ImplantSSP\.exe/ nocase ascii wide
                        $string3 = /\[\+\]\sAdding\syour\sDLL\sto\sthe\sLSA\sSecurity\sPackages\sregistry\skey/ nocase ascii wide
                        $string4 = /\[\+\]\sRegistry\skey\sset\.\sDLL\swill\sbe\sloaded\son\sreboot/ nocase ascii wide
                        $string5 = /\[\+\]\sSafety\schecks\spassed\.\sImplanting\syour\sDLL/ nocase ascii wide
                        $string6 = /\\ImplantSSP\.exe/ nocase ascii wide
                        $string7 = /ImplantSSP\.csproj/ nocase ascii wide
                        $string8 = "master/ImplantSSP/" nocase ascii wide

    condition:
        any of them
}