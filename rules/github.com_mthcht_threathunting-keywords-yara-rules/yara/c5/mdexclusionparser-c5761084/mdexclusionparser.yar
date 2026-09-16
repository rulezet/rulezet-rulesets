rule MDExclusionParser
{
    meta:
        description = "Detection patterns for the tool 'MDExclusionParser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MDExclusionParser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sInvoke\-MDExclusionParser\.ps1/ nocase ascii wide
                        $string2 = /\/Invoke\-MDExclusionParser\.ps1/ nocase ascii wide
                        $string3 = /\/MDExclusionParser\.git/ nocase ascii wide
                        $string4 = /\[i\]\sParsing\sfor\sDefender\sExclusions/ nocase ascii wide
                        $string5 = /\\Invoke\-MDExclusionParser\.ps1/ nocase ascii wide
                        $string6 = "Invoke-MDExclusionParser " nocase ascii wide
                        $string7 = "MDExclusionParser-main" nocase ascii wide
                        $string8 = "ViziosDe/MDExclusionParser" nocase ascii wide

    condition:
        any of them
}