rule rule_bulletpassview_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bulletpassview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bulletpassview"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bulletpassview_offensive_tool_keyword = ">BulletsPassView<" nocase ascii wide
                        $string2_bulletpassview_offensive_tool_keyword = /BulletsPassView\.exe/ nocase ascii wide
                        $string3_bulletpassview_offensive_tool_keyword = /BulletsPassView\.zip/ nocase ascii wide
                        $string4_bulletpassview_offensive_tool_keyword = /BulletsPassView_setup\.exe/ nocase ascii wide
                        $string5_bulletpassview_offensive_tool_keyword = /BulletsPassView_x64\.exe/ nocase ascii wide
                        $string6_bulletpassview_offensive_tool_keyword = "e71cda5e7c018f18aefcdfbce171cfeee7b8d556e5036d8b8f0864efc5f2156b" nocase ascii wide

    condition:
        any of them
}