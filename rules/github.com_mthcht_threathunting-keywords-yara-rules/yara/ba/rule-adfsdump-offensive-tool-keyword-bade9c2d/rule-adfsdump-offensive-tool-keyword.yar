rule rule_ADFSDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADFSDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADFSDump_offensive_tool_keyword = /\!\!\!\sAre\syou\ssure\syou\sare\srunning\sas\sthe\sAD\sFS\sservice\saccount\?/ nocase ascii wide
                        $string2_ADFSDump_offensive_tool_keyword = "## Extracting Private Key from Active Directory Store" nocase ascii wide
                        $string3_ADFSDump_offensive_tool_keyword = /\/ADFSDump\.git/ nocase ascii wide
                        $string4_ADFSDump_offensive_tool_keyword = /\\ADFSDump\./ nocase ascii wide
                        $string5_ADFSDump_offensive_tool_keyword = /\\ADFSDump\\/ nocase ascii wide
                        $string6_ADFSDump_offensive_tool_keyword = /\\ADFSDump\\/ nocase ascii wide
                        $string7_ADFSDump_offensive_tool_keyword = /\\ADFSDump\-master/ nocase ascii wide
                        $string8_ADFSDump_offensive_tool_keyword = ">ADFSDump<" nocase ascii wide
                        $string9_ADFSDump_offensive_tool_keyword = "46d1f15077f064a99b06bb115ba498581828ff8b712b2c41f6eb602538077035" nocase ascii wide
                        $string10_ADFSDump_offensive_tool_keyword = "7aa369f9365c35abe1cfea6a209a8a6071d7af3377a357f94721860c02e4d332" nocase ascii wide
                        $string11_ADFSDump_offensive_tool_keyword = "9EE27D63-6AC9-4037-860B-44E91BAE7F0D" nocase ascii wide
                        $string12_ADFSDump_offensive_tool_keyword = /ADFSDump\.csproj/ nocase ascii wide
                        $string13_ADFSDump_offensive_tool_keyword = /ADFSDump\.exe/ nocase ascii wide
                        $string14_ADFSDump_offensive_tool_keyword = /ADFSDump\.exe/ nocase ascii wide
                        $string15_ADFSDump_offensive_tool_keyword = /ADFSDump\.sln/ nocase ascii wide
                        $string16_ADFSDump_offensive_tool_keyword = "mandiant/ADFSDump" nocase ascii wide

    condition:
        any of them
}