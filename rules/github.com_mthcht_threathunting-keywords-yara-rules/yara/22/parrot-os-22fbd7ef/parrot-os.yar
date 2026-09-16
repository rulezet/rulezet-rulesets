rule parrot_os
{
    meta:
        description = "Detection patterns for the tool 'parrot os' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "parrot os"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " parrot main "
                        $string2 = /\sparrot\.run\//
                        $string3 = " parrot-backports "
                        $string4 = " parrot-security "
                        $string5 = /\/deb\.parrot\.sh\//
                        $string6 = /\/parrot\/iso\/.{0,1000}\.iso/
                        $string7 = "/parrot-mirror/"
                        $string8 = "/parrot-on-docker/"
                        $string9 = "/parrotsec/"
                        $string10 = /bunny\.deb\.parrot\.sh\//
                        $string11 = /edge1\.parrot\.run/
                        $string12 = /mirrors\.aliyun\.com\/parrot/
                        $string13 = /parrot.{0,1000}security\.vdi/
                        $string14 = /parrotsec\.org\/download\//
                        $string15 = /Parrot\-security\-.{0,1000}\.iso/

    condition:
        any of them
}