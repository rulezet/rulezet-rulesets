rule rule_ruby_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ruby' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ruby"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ruby_greyware_tool_keyword = /ruby\s\-rsocket\s.{0,1000}TCPSocket\.open\(.{0,1000}exec\ssprintf.{0,1000}\/bin\/sh\s\-i\s/

    condition:
        any of them
}