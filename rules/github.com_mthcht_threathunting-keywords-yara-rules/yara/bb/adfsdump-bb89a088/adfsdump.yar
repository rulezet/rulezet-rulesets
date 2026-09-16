rule ADFSDump
{
    meta:
        description = "Detection patterns for the tool 'ADFSDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\!\!\!\sAre\syou\ssure\syou\sare\srunning\sas\sthe\sAD\sFS\sservice\saccount\?/ nocase ascii wide
                        $string2 = "## Extracting Private Key from Active Directory Store" nocase ascii wide
                        $string3 = /\/ADFSDump\.git/ nocase ascii wide
                        $string4 = /\\ADFSDump\./ nocase ascii wide
                        $string5 = /\\ADFSDump\\/ nocase ascii wide
                        $string6 = /\\ADFSDump\\/ nocase ascii wide
                        $string7 = /\\ADFSDump\-master/ nocase ascii wide
                        $string8 = ">ADFSDump<" nocase ascii wide
                        $string9 = "46d1f15077f064a99b06bb115ba498581828ff8b712b2c41f6eb602538077035" nocase ascii wide
                        $string10 = "7aa369f9365c35abe1cfea6a209a8a6071d7af3377a357f94721860c02e4d332" nocase ascii wide
                        $string11 = "9EE27D63-6AC9-4037-860B-44E91BAE7F0D" nocase ascii wide
                        $string12 = /ADFSDump\.csproj/ nocase ascii wide
                        $string13 = /ADFSDump\.exe/ nocase ascii wide
                        $string14 = /ADFSDump\.exe/ nocase ascii wide
                        $string15 = /ADFSDump\.sln/ nocase ascii wide
                        $string16 = "mandiant/ADFSDump" nocase ascii wide

    condition:
        any of them
}