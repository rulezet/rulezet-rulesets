rule BlankOBF
{
    meta:
        description = "Detection patterns for the tool 'BlankOBF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlankOBF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sBlankOBFv2\.py/ nocase ascii wide
                        $string2 = /\/BlankOBF\.git/ nocase ascii wide
                        $string3 = /\/BlankOBFv2\.py/ nocase ascii wide
                        $string4 = /\\BlankOBFv2\.py/ nocase ascii wide
                        $string5 = "bc4657ac480d1f46349254c1d217dba4725fe54bbfa5fe7492c6a1bf1c6afebe" nocase ascii wide
                        $string6 = "Blank-c/BlankOBF" nocase ascii wide
                        $string7 = "BlankOBF v2: Obfuscates Python code to make it unreadable and hard to reverse" nocase ascii wide
                        $string8 = "from BlankOBFv2 import " nocase ascii wide
                        $string9 = "You managed to break through BlankOBF v2; Give yourself a pat on your back!" nocase ascii wide

    condition:
        any of them
}