rule rule_Invoke_RunAsWithCert_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-RunAsWithCert' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-RunAsWithCert"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_RunAsWithCert_offensive_tool_keyword = /\.pfx\s\-Domain\s.{0,1000}\s\-PatchLsass/ nocase ascii wide
                        $string2_Invoke_RunAsWithCert_offensive_tool_keyword = /\/Invoke\-RunAsWithCert\.git/ nocase ascii wide
                        $string3_Invoke_RunAsWithCert_offensive_tool_keyword = "75dcce94ecc2df9392b92c2be705c72626a22c7c8fad662c8a1f3b4dba0228d8" nocase ascii wide
                        $string4_Invoke_RunAsWithCert_offensive_tool_keyword = "Invoke-RunAsWithCert" nocase ascii wide
                        $string5_Invoke_RunAsWithCert_offensive_tool_keyword = "synacktiv/Invoke-RunAsWithCert" nocase ascii wide

    condition:
        any of them
}