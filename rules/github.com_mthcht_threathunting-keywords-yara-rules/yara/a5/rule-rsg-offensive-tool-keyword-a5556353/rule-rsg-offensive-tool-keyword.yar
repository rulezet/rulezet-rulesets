rule rule_rsg_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rsg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsg"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rsg_offensive_tool_keyword = " nc -n -v -l -s "
                        $string2_rsg_offensive_tool_keyword = /\s\-NoP\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Command\sNew\-Object\sSystem\.Net\.Sockets\./ nocase ascii wide
                        $string3_rsg_offensive_tool_keyword = /\s\-NoP\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Command\sNew\-Object\sSystem\.Net\.Sockets\.TCPClient/ nocase ascii wide
                        $string4_rsg_offensive_tool_keyword = "/bin/sh -i <&3 >&3 2>&3"
                        $string5_rsg_offensive_tool_keyword = "/usr/local/bin/rsg"
                        $string6_rsg_offensive_tool_keyword = "64cd8640e2b53358f8fbafbcbded6db53e1acd49fe4ccc8196c8ed17c551bc70" nocase ascii wide
                        $string7_rsg_offensive_tool_keyword = "b3804cac36175125199ddd8f6840749ead5c723d9641670d244d0a487fcf555c" nocase ascii wide
                        $string8_rsg_offensive_tool_keyword = "ebdac49d15f37cc60cb5e755b10743512ececf134126e0ac4a024cb1149ae76f" nocase ascii wide
                        $string9_rsg_offensive_tool_keyword = /mthbernardes.{0,1000}rsg/ nocase ascii wide
                        $string10_rsg_offensive_tool_keyword = "mthbernardes/rsg" nocase ascii wide
                        $string11_rsg_offensive_tool_keyword = "nc -c /bin/sh "
                        $string12_rsg_offensive_tool_keyword = /php\s\-r\s.{0,1000}fsockopen.{0,1000}exec\(.{0,1000}\/bin\/sh/
                        $string13_rsg_offensive_tool_keyword = /powershell\s\-nop\s\-c\s\\"\\"\$client\s\=\sNew\-Object\sSystem\.Net\.Sockets\.TCPClient/ nocase ascii wide
                        $string14_rsg_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\s\'.{0,1000}\=TCPSocket\.new\(/ nocase ascii wide
                        $string15_rsg_offensive_tool_keyword = /socat\.exe\s\-d\s\-d\sTCP4\:/ nocase ascii wide

    condition:
        any of them
}