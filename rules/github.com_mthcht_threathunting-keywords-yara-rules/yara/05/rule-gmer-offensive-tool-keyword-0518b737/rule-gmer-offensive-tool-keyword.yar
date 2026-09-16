rule rule_gmer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gmer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gmer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gmer_offensive_tool_keyword = /\/gmer\.exe/ nocase ascii wide
                        $string2_gmer_offensive_tool_keyword = /\/gmer64\.sys/
                        $string3_gmer_offensive_tool_keyword = /\\gmer\.exe/ nocase ascii wide
                        $string4_gmer_offensive_tool_keyword = /\\gmer64\.pdb/ nocase ascii wide
                        $string5_gmer_offensive_tool_keyword = /\\gmer64\.sys/ nocase ascii wide
                        $string6_gmer_offensive_tool_keyword = /\\Release\\gmer\.pdb/ nocase ascii wide
                        $string7_gmer_offensive_tool_keyword = /\>GMER\sDriver\shttp\:\/\/www\.gmer\.net\</ nocase ascii wide
                        $string8_gmer_offensive_tool_keyword = "18c909a2b8c5e16821d6ef908f56881aa0ecceeaccb5fa1e54995935fcfd12f7" nocase ascii wide
                        $string9_gmer_offensive_tool_keyword = "de3abde117d7eacbb638bc7d0151f929cf80a4bb5e5beb1e390839e96fc6722a" nocase ascii wide
                        $string10_gmer_offensive_tool_keyword = "e8a3e804a96c716a3e9b69195db6ffb0d33e2433af871e4d4e1eab3097237173" nocase ascii wide
                        $string11_gmer_offensive_tool_keyword = "e8a3e804a96c716a3e9b69195db6ffb0d33e2433af871e4d4e1eab3097237173" nocase ascii wide
                        $string12_gmer_offensive_tool_keyword = /http\:\/\/www\.gmer\.net\/\#files/ nocase ascii wide
                        $string13_gmer_offensive_tool_keyword = /http\:\/\/www2\.gmer\.net\/download/ nocase ascii wide
                        $string14_gmer_offensive_tool_keyword = /http\:\/\/www2\.gmer\.net\/gmer\.zip/ nocase ascii wide

    condition:
        any of them
}