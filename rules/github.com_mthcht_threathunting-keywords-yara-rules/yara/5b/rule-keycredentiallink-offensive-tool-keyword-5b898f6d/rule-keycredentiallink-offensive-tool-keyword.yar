rule rule_KeyCredentialLink_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KeyCredentialLink' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeyCredentialLink"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KeyCredentialLink_offensive_tool_keyword = /\s\/domain\:.{0,1000}\s\/dc\:.{0,1000}\s\/getcredentials\s\/nowrap/ nocase ascii wide
                        $string2_KeyCredentialLink_offensive_tool_keyword = /\sKeyCredentialLink\.ps1/ nocase ascii wide
                        $string3_KeyCredentialLink_offensive_tool_keyword = /\.exe\sasktgt\s\/user\:.{0,1000}\s\/certificate\:.{0,1000}\s\/password\:/ nocase ascii wide
                        $string4_KeyCredentialLink_offensive_tool_keyword = /\/KeyCredentialLink\.git/ nocase ascii wide
                        $string5_KeyCredentialLink_offensive_tool_keyword = /\/KeyCredentialLink\.ps1/ nocase ascii wide
                        $string6_KeyCredentialLink_offensive_tool_keyword = /\\KeyCredentialLink\.ps1/ nocase ascii wide
                        $string7_KeyCredentialLink_offensive_tool_keyword = /\\Public\\Documents\\DSInternals/ nocase ascii wide
                        $string8_KeyCredentialLink_offensive_tool_keyword = "1257077a68f9725d863947e0931a44727fceaad6565b73b9f8d873cc3d028e00" nocase ascii wide
                        $string9_KeyCredentialLink_offensive_tool_keyword = "5db4c8112942c658a4f14d16fff13781dd705273c0050b2ada09ec79c7cb7c87" nocase ascii wide
                        $string10_KeyCredentialLink_offensive_tool_keyword = "Add-KeyCredentials -target " nocase ascii wide
                        $string11_KeyCredentialLink_offensive_tool_keyword = "AERTSW50ZXJuYWxzXHg4Nlx2Y3J1bnRpbWUxNDBfdGhyZWFkcy5kbGxQSwECFAAUAAAACAAnnY1YrbP4grERAAA9RQAADwAAAAAAAAAAAAAAAABk7yEARFNJbnRlcm5hbHMuY2F0UEsFBgAAAAAwADAAdRAAAEIBIgAAAA==" nocase ascii wide
                        $string12_KeyCredentialLink_offensive_tool_keyword = "Clear-KeyCredentials -target " nocase ascii wide
                        $string13_KeyCredentialLink_offensive_tool_keyword = "Leo4j/KeyCredentialLink" nocase ascii wide
                        $string14_KeyCredentialLink_offensive_tool_keyword = "List-KeyCredentials -target " nocase ascii wide

    condition:
        any of them
}