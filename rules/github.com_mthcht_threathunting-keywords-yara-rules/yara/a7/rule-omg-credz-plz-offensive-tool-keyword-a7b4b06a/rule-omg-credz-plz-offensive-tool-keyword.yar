rule rule_OMG_Credz_Plz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OMG-Credz-Plz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OMG-Credz-Plz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OMG_Credz_Plz_offensive_tool_keyword = /Credz\-Plz\.ps1/ nocase ascii wide
                        $string2_OMG_Credz_Plz_offensive_tool_keyword = /Credz\-Plz\-Execute\.txt/ nocase ascii wide
                        $string3_OMG_Credz_Plz_offensive_tool_keyword = /Invoke\-RestMethod\s\-Uri\shttps\:\/\/content\.dropboxapi\.com\/2\/files\/upload\s\-Method\sPost\s\s\-InFile\s.{0,1000}\s\-Headers\s/ nocase ascii wide
                        $string4_OMG_Credz_Plz_offensive_tool_keyword = "-OMG-Credz-Plz" nocase ascii wide

    condition:
        any of them
}