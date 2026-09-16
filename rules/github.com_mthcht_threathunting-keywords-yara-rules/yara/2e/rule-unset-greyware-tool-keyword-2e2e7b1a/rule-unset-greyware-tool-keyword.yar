rule rule_unset_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'unset' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unset"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_unset_greyware_tool_keyword = /unset\sHISTFILE\s\&\&\sHISTSIZE\=0\s\&\&\srm\s\-f\s\$HISTFILE\s\&\&\sunset\sHISTFILE/
                        $string2_unset_greyware_tool_keyword = "unset HISTFILE"
                        $string3_unset_greyware_tool_keyword = "unset HISTFILE"
                        $string4_unset_greyware_tool_keyword = "unset HISTFILESIZE"
                        $string5_unset_greyware_tool_keyword = "unset HISTSIZE"

    condition:
        any of them
}