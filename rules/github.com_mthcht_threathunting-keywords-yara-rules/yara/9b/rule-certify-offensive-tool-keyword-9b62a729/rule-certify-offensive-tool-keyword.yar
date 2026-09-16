rule rule_Certify_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Certify' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Certify"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Certify_offensive_tool_keyword = /\/Certify\.exe/ nocase ascii wide
                        $string2_Certify_offensive_tool_keyword = /\[\!\]\sThere\sare\sno\senterprise\sCAs\sand\stherefore\sno\sone\scan\srequest\scertificates/ nocase ascii wide
                        $string3_Certify_offensive_tool_keyword = /\\Certify\.exe/ nocase ascii wide
                        $string4_Certify_offensive_tool_keyword = /Certify\.exe\s/ nocase ascii wide
                        $string5_Certify_offensive_tool_keyword = "ImpersonateLoggedOnUser worked, but thread is not running as SYSTEM" nocase ascii wide

    condition:
        any of them
}