rule rule_php_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'php' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "php"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_php_greyware_tool_keyword = /php\s\-r\s.{0,1000}\$sock\=fsockopen\(.{0,1000}exec\(.{0,1000}\/bin\/sh\s\-i\s\<\&3\s\>\&3\s2\>\&3/

    condition:
        any of them
}