rule ldapsearch_ad
{
    meta:
        description = "Detection patterns for the tool 'ldapsearch-ad' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapsearch-ad"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-server\s.{0,1000}\s\-\-type\spass\-pols/
                        $string2 = " --type asreproast"
                        $string3 = " --type search-spn"
                        $string4 = /\/ldapsearch\-ad\.git/
                        $string5 = /ldapsearchad\.py/
                        $string6 = /ldapsearch\-ad\.py/

    condition:
        any of them
}