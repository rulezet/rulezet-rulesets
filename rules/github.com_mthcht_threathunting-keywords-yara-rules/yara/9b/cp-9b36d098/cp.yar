rule cp
{
    meta:
        description = "Detection patterns for the tool 'cp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "cp /bin/bash /tmp/"
                        $string2 = "cp /bin/sh /tmp/"
                        $string3 = "cp /etc/passwd"
                        $string4 = "cp /etc/shadow"
                        $string5 = "cp -i /bin/bash /tmp/"
                        $string6 = "cp -i /bin/sh /tmp/"

    condition:
        any of them
}