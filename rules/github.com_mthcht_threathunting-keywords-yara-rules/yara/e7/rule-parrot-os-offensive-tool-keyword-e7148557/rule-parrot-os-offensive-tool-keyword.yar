rule rule_parrot_os_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'parrot os' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "parrot os"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_parrot_os_offensive_tool_keyword = " parrot main "
                        $string2_parrot_os_offensive_tool_keyword = /\sparrot\.run\//
                        $string3_parrot_os_offensive_tool_keyword = " parrot-backports "
                        $string4_parrot_os_offensive_tool_keyword = " parrot-security "
                        $string5_parrot_os_offensive_tool_keyword = /\/deb\.parrot\.sh\//
                        $string6_parrot_os_offensive_tool_keyword = /\/parrot\/iso\/.{0,1000}\.iso/
                        $string7_parrot_os_offensive_tool_keyword = "/parrot-mirror/"
                        $string8_parrot_os_offensive_tool_keyword = "/parrot-on-docker/"
                        $string9_parrot_os_offensive_tool_keyword = "/parrotsec/"
                        $string10_parrot_os_offensive_tool_keyword = /bunny\.deb\.parrot\.sh\//
                        $string11_parrot_os_offensive_tool_keyword = /edge1\.parrot\.run/
                        $string12_parrot_os_offensive_tool_keyword = /mirrors\.aliyun\.com\/parrot/
                        $string13_parrot_os_offensive_tool_keyword = /parrot.{0,1000}security\.vdi/
                        $string14_parrot_os_offensive_tool_keyword = /parrotsec\.org\/download\//
                        $string15_parrot_os_offensive_tool_keyword = /Parrot\-security\-.{0,1000}\.iso/

    condition:
        any of them
}