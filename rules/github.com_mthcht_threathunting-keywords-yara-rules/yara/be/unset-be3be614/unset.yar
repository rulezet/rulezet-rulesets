rule unset
{
    meta:
        description = "Detection patterns for the tool 'unset' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unset"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /unset\sHISTFILE\s\&\&\sHISTSIZE\=0\s\&\&\srm\s\-f\s\$HISTFILE\s\&\&\sunset\sHISTFILE/
                        $string2 = "unset HISTFILE"
                        $string3 = "unset HISTFILE"
                        $string4 = "unset HISTFILESIZE"
                        $string5 = "unset HISTSIZE"

    condition:
        any of them
}