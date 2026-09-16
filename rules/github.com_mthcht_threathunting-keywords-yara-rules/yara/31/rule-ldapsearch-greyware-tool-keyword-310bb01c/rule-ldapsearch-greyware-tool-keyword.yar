rule rule_ldapsearch_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ldapsearch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapsearch"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ldapsearch_greyware_tool_keyword = /ldapsearch\s.{0,1000}\sldap\:\/\//
                        $string2_ldapsearch_greyware_tool_keyword = /ldapsearch\s\-x\s\-h\s.{0,1000}\s\-s\sbase/
                        $string3_ldapsearch_greyware_tool_keyword = /ldapsearch\s\-h\s.{0,1000}\s\-x/

    condition:
        any of them
}