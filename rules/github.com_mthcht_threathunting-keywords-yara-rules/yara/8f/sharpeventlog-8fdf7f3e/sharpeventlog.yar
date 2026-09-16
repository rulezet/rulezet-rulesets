rule SharpEventLog
{
    meta:
        description = "Detection patterns for the tool 'SharpEventLog' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEventLog"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpEventLog\.exe/ nocase ascii wide
                        $string2 = /\/SharpEventLog\.git/ nocase ascii wide
                        $string3 = /\\SharpEventLog\.csproj/ nocase ascii wide
                        $string4 = /\\SharpEventLog\.exe/ nocase ascii wide
                        $string5 = /\\SharpEventLog\.pdb/ nocase ascii wide
                        $string6 = /\\SharpEventLog\.sln/ nocase ascii wide
                        $string7 = /\\SharpEventLog\-master/ nocase ascii wide
                        $string8 = ">SharpEventLog<" nocase ascii wide
                        $string9 = "20ee05dd8552f0e3600b0d597d202e6d9baf1c1f30029d8a4773bb172016ce42" nocase ascii wide
                        $string10 = "3bf281b68fa29aece79cd0126a3b4552720cefe1045dc974b82523e439a11694" nocase ascii wide
                        $string11 = "4CA05D5C-AF6B-4F45-81E0-788BAA8D11A2" nocase ascii wide
                        $string12 = "9f4885b3b55f370d05e9426ba900cfa8daaa785129d6d80e576d16e4d497f6c8" nocase ascii wide
                        $string13 = "bb91387aea9bb46572a1b0a0be195f8ca26f47c7e5dc42c04b5b8a614a686c31" nocase ascii wide
                        $string14 = "bb91387aea9bb46572a1b0a0be195f8ca26f47c7e5dc42c04b5b8a614a686c31" nocase ascii wide
                        $string15 = "uknowsec/SharpEventLog" nocase ascii wide

    condition:
        any of them
}