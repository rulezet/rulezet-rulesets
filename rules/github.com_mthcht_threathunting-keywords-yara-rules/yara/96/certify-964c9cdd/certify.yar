rule Certify
{
    meta:
        description = "Detection patterns for the tool 'Certify' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Certify"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Certify\.exe/ nocase ascii wide
                        $string2 = /\[\!\]\sThere\sare\sno\senterprise\sCAs\sand\stherefore\sno\sone\scan\srequest\scertificates/ nocase ascii wide
                        $string3 = /\\Certify\.exe/ nocase ascii wide
                        $string4 = /Certify\.exe\s/ nocase ascii wide
                        $string5 = "ImpersonateLoggedOnUser worked, but thread is not running as SYSTEM" nocase ascii wide

    condition:
        any of them
}