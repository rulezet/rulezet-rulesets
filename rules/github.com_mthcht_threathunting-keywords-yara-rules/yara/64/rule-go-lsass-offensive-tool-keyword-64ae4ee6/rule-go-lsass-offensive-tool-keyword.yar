rule rule_go_lsass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'go-lsass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "go-lsass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_go_lsass_offensive_tool_keyword = /\/go\-lsass\.exe/ nocase ascii wide
                        $string2_go_lsass_offensive_tool_keyword = /\/go\-lsass\.git/ nocase ascii wide
                        $string3_go_lsass_offensive_tool_keyword = "/go-lsass/releases" nocase ascii wide
                        $string4_go_lsass_offensive_tool_keyword = /\/go\-lsass\-master\.zip/ nocase ascii wide
                        $string5_go_lsass_offensive_tool_keyword = /\\go\-lsass\.exe/ nocase ascii wide
                        $string6_go_lsass_offensive_tool_keyword = /\\go\-lsass\-master\.zip/ nocase ascii wide
                        $string7_go_lsass_offensive_tool_keyword = /\\go\-lsass\-master\\/ nocase ascii wide
                        $string8_go_lsass_offensive_tool_keyword = "16386980a156fc6e9219ba230c5fd2759e4b43dff9261487598e7d0ecfe78ae0" nocase ascii wide
                        $string9_go_lsass_offensive_tool_keyword = "455a614b6dd52b17b4af639045bd0c3c3ddad152334607978ec9e915553246e9" nocase ascii wide
                        $string10_go_lsass_offensive_tool_keyword = "a7e8aade00d2cd5aeb6ec40d5b64f6cac88f120efb4efb719567e758af5892c2" nocase ascii wide
                        $string11_go_lsass_offensive_tool_keyword = "db5a054172dcde3aebfb86b08e3bf8992f9df3d22e2028fd5154c647e7361ceb" nocase ascii wide
                        $string12_go_lsass_offensive_tool_keyword = "go-lsass --host "
                        $string13_go_lsass_offensive_tool_keyword = "jfjallid/go-lsass" nocase ascii wide
                        $string14_go_lsass_offensive_tool_keyword = "Successfully downloaded the LSASS dump into local file" nocase ascii wide

    condition:
        any of them
}