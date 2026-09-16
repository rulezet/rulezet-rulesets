rule rule_SunCrypt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SunCrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SunCrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SunCrypt_offensive_tool_keyword = /\.onion\/chat\.html\?/ nocase ascii wide
                        $string2_SunCrypt_offensive_tool_keyword = /\<h2\>Why\spay\sus\?\<\/h2\>/ nocase ascii wide
                        $string3_SunCrypt_offensive_tool_keyword = /YOUR_FILES_ARE_ENCRYPTED\.HTML/ nocase ascii wide

    condition:
        any of them
}