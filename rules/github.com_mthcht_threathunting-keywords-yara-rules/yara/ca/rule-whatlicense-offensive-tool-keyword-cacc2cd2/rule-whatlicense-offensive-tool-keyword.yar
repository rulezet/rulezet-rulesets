rule rule_whatlicense_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'whatlicense' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whatlicense"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_whatlicense_offensive_tool_keyword = /\.exe\s\-t\swl\-extract\.dll\s\-d\s.{0,1000}\.dat\s\-r\s.{0,1000}\.rsa\s\-.{0,1000}\.exe/ nocase ascii wide
                        $string2_whatlicense_offensive_tool_keyword = /\/whatlicense\.git/ nocase ascii wide
                        $string3_whatlicense_offensive_tool_keyword = /\\whatlicense\-main\\/ nocase ascii wide
                        $string4_whatlicense_offensive_tool_keyword = /\\wl_log\.txt/ nocase ascii wide
                        $string5_whatlicense_offensive_tool_keyword = /\\wl\-lic\.exe/ nocase ascii wide
                        $string6_whatlicense_offensive_tool_keyword = /\\wl\-lic\.pdb/ nocase ascii wide
                        $string7_whatlicense_offensive_tool_keyword = "639EF517-FCFC-408E-9500-71F0DC0458DB" nocase ascii wide
                        $string8_whatlicense_offensive_tool_keyword = "CC127443-2519-4E04-8865-A6887658CDE5" nocase ascii wide
                        $string9_whatlicense_offensive_tool_keyword = "charlesnathansmith/whatlicense" nocase ascii wide
                        $string10_whatlicense_offensive_tool_keyword = /whatlicense\-main\.zip/ nocase ascii wide
                        $string11_whatlicense_offensive_tool_keyword = /wl\-lic\s\-d\s.{0,1000}\.dat\s\-r\s.{0,1000}\.rsa/ nocase ascii wide
                        $string12_whatlicense_offensive_tool_keyword = /wl\-lic\s\-h\sHWID\s\-m\smain_hash\s\-d\sregkey2\.dat\s\-r\sregkey2\.rsa/ nocase ascii wide

    condition:
        any of them
}