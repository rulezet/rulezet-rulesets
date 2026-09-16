rule rule_pywhisker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pywhisker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pywhisker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pywhisker_offensive_tool_keyword = /\s\-u\s.{0,1000}\s\-d\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-k\s\-\-no\-pass\s\-\-target\s.{0,1000}\s\-\-action\s\\"list\\"/ nocase ascii wide
                        $string2_pywhisker_offensive_tool_keyword = /\.py\s\-d\s\\"test\.local\\"\s\-u\s\\"john\\"\s\-p\s\\"password123\\"\s\-\-target\s\\"user2\\"\s\-\-action\s\\"list\\"\s\-\-dc\-ip\s\\"10\.10\.10\.1\\"/ nocase ascii wide
                        $string3_pywhisker_offensive_tool_keyword = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\s.{0,1000}\s\-\-export\sPEM/ nocase ascii wide
                        $string4_pywhisker_offensive_tool_keyword = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\\"add\\"\s\-\-filename\s.{0,1000}\s/ nocase ascii wide
                        $string5_pywhisker_offensive_tool_keyword = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\\"clear\\".{0,1000}\s/ nocase ascii wide
                        $string6_pywhisker_offensive_tool_keyword = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\\"info\\"\s\-\-device\-id\s/ nocase ascii wide
                        $string7_pywhisker_offensive_tool_keyword = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\\"list\\"\s/ nocase ascii wide
                        $string8_pywhisker_offensive_tool_keyword = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\\"remove\\"\s\-\-device\-id\s/ nocase ascii wide
                        $string9_pywhisker_offensive_tool_keyword = /\/pywhisker\.git/ nocase ascii wide
                        $string10_pywhisker_offensive_tool_keyword = /getnthash\.py\s\-key\s/ nocase ascii wide
                        $string11_pywhisker_offensive_tool_keyword = /gettgtpkinit\.py\s\-cert\-pfx\s/ nocase ascii wide
                        $string12_pywhisker_offensive_tool_keyword = /Initializing\sdomainDumper\(\)/ nocase ascii wide
                        $string13_pywhisker_offensive_tool_keyword = /lmhash.{0,1000}aad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
                        $string14_pywhisker_offensive_tool_keyword = /pywhisker\.py/ nocase ascii wide
                        $string15_pywhisker_offensive_tool_keyword = "pywhisker-main" nocase ascii wide
                        $string16_pywhisker_offensive_tool_keyword = "ShutdownRepo/pywhisker" nocase ascii wide

    condition:
        any of them
}