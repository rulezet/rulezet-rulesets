rule SharpHide
{
    meta:
        description = "Detection patterns for the tool 'SharpHide' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpHide"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpHide\.git/ nocase ascii wide
                        $string2 = /\/SharpHide\.git/ nocase ascii wide
                        $string3 = /\[\+\]\sSharpHide\srunning\sas\selevated\suser/ nocase ascii wide
                        $string4 = /\[\+\]\sSharpHide\srunning\sas\snormal\suser/ nocase ascii wide
                        $string5 = /\\Windows\\Temp\\Bla\.exe/ nocase ascii wide
                        $string6 = "443D8CBF-899C-4C22-B4F6-B7AC202D4E37" nocase ascii wide
                        $string7 = "66504e8c044a01ed3ef2a97dd36de68b7b1913d737d6ad4e6bd7778d80dec92f" nocase ascii wide
                        $string8 = "6ff0ec2a775575ab2724c254aa386c44155453c1ae020446a6fb5b0535de65d3" nocase ascii wide
                        $string9 = "outflanknl/SharpHide" nocase ascii wide
                        $string10 = "SharpHide running as elevated user" nocase ascii wide
                        $string11 = /SharpHide\.csproj/ nocase ascii wide
                        $string12 = /SharpHide\.exe/ nocase ascii wide
                        $string13 = /SharpHide\.sln/ nocase ascii wide
                        $string14 = "SharpHide-master" nocase ascii wide

    condition:
        any of them
}