rule SharpEdge
{
    meta:
        description = "Detection patterns for the tool 'SharpEdge' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEdge"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpEdge\.exe/ nocase ascii wide
                        $string2 = /\/SharpEdge\.git/ nocase ascii wide
                        $string3 = /\\SharpEdge\.csproj/ nocase ascii wide
                        $string4 = /\\SharpEdge\.exe/ nocase ascii wide
                        $string5 = /\\SharpEdge\.sln/ nocase ascii wide
                        $string6 = /\\SharpEdge\-master/ nocase ascii wide
                        $string7 = "0d21ae4c38549782f8b066155b671b2a356721209a5ecaa64bba6edcc6e2f97e" nocase ascii wide
                        $string8 = "2388c7f7f1073b922d235f675e32e1b6b8809dcef1cce1113bf712402cbad1cd" nocase ascii wide
                        $string9 = "75f068e65a36c0dfcd7b59c00ab3a0e73f6bc07ca84091f472caada25e32cfcd" nocase ascii wide
                        $string10 = "D116BEC7-8DEF-4FCE-BF84-C8504EF4E481" nocase ascii wide
                        $string11 = "rvrsh3ll/SharpEdge" nocase ascii wide

    condition:
        any of them
}