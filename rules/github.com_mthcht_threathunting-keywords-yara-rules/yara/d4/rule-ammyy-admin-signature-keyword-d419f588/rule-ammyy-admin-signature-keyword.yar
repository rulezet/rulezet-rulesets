rule rule_Ammyy_Admin_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ammyy Admin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ammyy Admin"
        rule_category = "signature_keyword"

    strings:
                        $string1_Ammyy_Admin_signature_keyword = "PUA:Win32/AmmyyAdmin" nocase ascii wide
                        $string2_Ammyy_Admin_signature_keyword = "PUA:Win32/AmmyyAdmin" nocase ascii wide
                        $string3_Ammyy_Admin_signature_keyword = "RemoteAccess:Win32/AmmyAdmin" nocase ascii wide
                        $string4_Ammyy_Admin_signature_keyword = /SPR\/Ammyy\.R/ nocase ascii wide
                        $string5_Ammyy_Admin_signature_keyword = /Win32\.PUA\.AmmyyAdmin/ nocase ascii wide

    condition:
        any of them
}