rule rule_TokenFinder_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TokenFinder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenFinder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TokenFinder_offensive_tool_keyword = /\sTokenFinder\.py/ nocase ascii wide
                        $string2_TokenFinder_offensive_tool_keyword = /\/TokenFinder\.git/ nocase ascii wide
                        $string3_TokenFinder_offensive_tool_keyword = /\/TokenFinder\.py/ nocase ascii wide
                        $string4_TokenFinder_offensive_tool_keyword = /\\TokenFinder\.py/ nocase ascii wide
                        $string5_TokenFinder_offensive_tool_keyword = "doredry/TokenFinder" nocase ascii wide
                        $string6_TokenFinder_offensive_tool_keyword = "f049f7c98172f7696d6a0b312c91010720970f825eb4cff5c76c151e15f16951" nocase ascii wide
                        $string7_TokenFinder_offensive_tool_keyword = "python3 TokenFinder" nocase ascii wide
                        $string8_TokenFinder_offensive_tool_keyword = /Tokens\swere\sextracted\sto\stokens\.txt\!\sEnjoy/ nocase ascii wide

    condition:
        any of them
}