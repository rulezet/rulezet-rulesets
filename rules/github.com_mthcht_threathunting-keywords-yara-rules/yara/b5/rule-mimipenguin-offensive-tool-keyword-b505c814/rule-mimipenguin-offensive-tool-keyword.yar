rule rule_mimipenguin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mimipenguin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimipenguin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mimipenguin_offensive_tool_keyword = "/mimipenguin/releases/download/"
                        $string2_mimipenguin_offensive_tool_keyword = "37aaa060ddae57e5457ffc47f65362682d64da54775c2211705b8a7becc9e657"
                        $string3_mimipenguin_offensive_tool_keyword = "4d29f1251e4ef23a8e22ed209d547e84c421fa736b87646ddd8269c3a0e84093"
                        $string4_mimipenguin_offensive_tool_keyword = "7e158727df39c819d0b51228683ec4d1f1e9a949da480d6852445fa968814f46"
                        $string5_mimipenguin_offensive_tool_keyword = "af763332f70cf0137ebcb1d237e55a00c6fc0698982fec44fb012db4cb1be5df"
                        $string6_mimipenguin_offensive_tool_keyword = "c7d41f5a0fe15661632d70cde6b34787f87e4818d7c592ffa0c5b074fdb15712"
                        $string7_mimipenguin_offensive_tool_keyword = "e80bda100b7b75500bd6f4cc09e566e5467c784876bc01ba934ea8792daf8b11"
                        $string8_mimipenguin_offensive_tool_keyword = "f04f854c5bbfa8a33358efd2bb3e700e9be687250548a1cb21de1d661b5f04ff"
                        $string9_mimipenguin_offensive_tool_keyword = "fd8303c18bb8893e7d539cced09d4765805a37bd9ac5c92951ab381c70eec2a7"
                        $string10_mimipenguin_offensive_tool_keyword = /mimipenguin\./
                        $string11_mimipenguin_offensive_tool_keyword = /mimipenguin_.{0,1000}\.tar\.gz/

    condition:
        any of them
}