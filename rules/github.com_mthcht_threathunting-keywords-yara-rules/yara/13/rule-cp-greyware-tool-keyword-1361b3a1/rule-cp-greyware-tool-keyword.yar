rule rule_cp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_cp_greyware_tool_keyword = "cp /bin/bash /tmp/"
                        $string2_cp_greyware_tool_keyword = "cp /bin/sh /tmp/"
                        $string3_cp_greyware_tool_keyword = "cp /etc/passwd"
                        $string4_cp_greyware_tool_keyword = "cp /etc/shadow"
                        $string5_cp_greyware_tool_keyword = "cp -i /bin/bash /tmp/"
                        $string6_cp_greyware_tool_keyword = "cp -i /bin/sh /tmp/"

    condition:
        any of them
}