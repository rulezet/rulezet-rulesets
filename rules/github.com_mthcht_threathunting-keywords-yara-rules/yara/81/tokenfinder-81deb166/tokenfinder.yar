rule TokenFinder
{
    meta:
        description = "Detection patterns for the tool 'TokenFinder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenFinder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sTokenFinder\.py/ nocase ascii wide
                        $string2 = /\/TokenFinder\.git/ nocase ascii wide
                        $string3 = /\/TokenFinder\.py/ nocase ascii wide
                        $string4 = /\\TokenFinder\.py/ nocase ascii wide
                        $string5 = "doredry/TokenFinder" nocase ascii wide
                        $string6 = "f049f7c98172f7696d6a0b312c91010720970f825eb4cff5c76c151e15f16951" nocase ascii wide
                        $string7 = "python3 TokenFinder" nocase ascii wide
                        $string8 = /Tokens\swere\sextracted\sto\stokens\.txt\!\sEnjoy/ nocase ascii wide

    condition:
        any of them
}