rule rule_Ddexec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ddexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ddexec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Ddexec_offensive_tool_keyword = /\sbash\sddexec\.sh/
                        $string2_Ddexec_offensive_tool_keyword = /\sddexec\.sh\s/
                        $string3_Ddexec_offensive_tool_keyword = /\sddsc\.sh\s\-x/
                        $string4_Ddexec_offensive_tool_keyword = /\szsh\sddexec\.sh/
                        $string5_Ddexec_offensive_tool_keyword = /\/DDexec\.git/
                        $string6_Ddexec_offensive_tool_keyword = /\/ddexec\.sh/
                        $string7_Ddexec_offensive_tool_keyword = /\/ddsc\.sh\s/
                        $string8_Ddexec_offensive_tool_keyword = "4109aabda29898f764177befbe6967500dd724e511317a8232a046c91502b38f"
                        $string9_Ddexec_offensive_tool_keyword = "955201aaf535183bd7a881278fbaab7a16f742c150ff44e1d7ab0325c0c03baf"
                        $string10_Ddexec_offensive_tool_keyword = "arget13/DDexec"

    condition:
        any of them
}