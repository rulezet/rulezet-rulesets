rule bulletpassview
{
    meta:
        description = "Detection patterns for the tool 'bulletpassview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bulletpassview"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = ">BulletsPassView<" nocase ascii wide
                        $string2 = /BulletsPassView\.exe/ nocase ascii wide
                        $string3 = /BulletsPassView\.zip/ nocase ascii wide
                        $string4 = /BulletsPassView_setup\.exe/ nocase ascii wide
                        $string5 = /BulletsPassView_x64\.exe/ nocase ascii wide
                        $string6 = "e71cda5e7c018f18aefcdfbce171cfeee7b8d556e5036d8b8f0864efc5f2156b" nocase ascii wide

    condition:
        any of them
}