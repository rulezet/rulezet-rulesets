rule Ddexec
{
    meta:
        description = "Detection patterns for the tool 'Ddexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ddexec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbash\sddexec\.sh/
                        $string2 = /\sddexec\.sh\s/
                        $string3 = /\sddsc\.sh\s\-x/
                        $string4 = /\szsh\sddexec\.sh/
                        $string5 = /\/DDexec\.git/
                        $string6 = /\/ddexec\.sh/
                        $string7 = /\/ddsc\.sh\s/
                        $string8 = "4109aabda29898f764177befbe6967500dd724e511317a8232a046c91502b38f"
                        $string9 = "955201aaf535183bd7a881278fbaab7a16f742c150ff44e1d7ab0325c0c03baf"
                        $string10 = "arget13/DDexec"

    condition:
        any of them
}