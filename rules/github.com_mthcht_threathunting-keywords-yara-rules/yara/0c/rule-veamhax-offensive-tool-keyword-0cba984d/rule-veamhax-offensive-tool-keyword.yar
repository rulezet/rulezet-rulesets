rule rule_VeamHax_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VeamHax' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VeamHax"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_VeamHax_offensive_tool_keyword = /\s\-\-sql\s\\"EXEC\smaster\.\.xp_cmdshell/ nocase ascii wide
                        $string2_VeamHax_offensive_tool_keyword = " --sql \"EXEC sp_configure 'xp_cmdshell'" nocase ascii wide
                        $string3_VeamHax_offensive_tool_keyword = " --sql \"EXEC sp_configure 'xp_cmdshell', '1'" nocase ascii wide
                        $string4_VeamHax_offensive_tool_keyword = /\sVeeamHax\.exe/ nocase ascii wide
                        $string5_VeamHax_offensive_tool_keyword = /\/VeeamHax\.exe/ nocase ascii wide
                        $string6_VeamHax_offensive_tool_keyword = /\\VeeamHax\.exe/ nocase ascii wide
                        $string7_VeamHax_offensive_tool_keyword = /\\VeeamHax\.pdb/ nocase ascii wide
                        $string8_VeamHax_offensive_tool_keyword = /\\VeeamHax\.sln/ nocase ascii wide
                        $string9_VeamHax_offensive_tool_keyword = "2ffb7bfe8f888c083361a65e7a8a349ba1f6b16971522011f545029fb20b3fd1" nocase ascii wide
                        $string10_VeamHax_offensive_tool_keyword = "59c2e7b63bbfe6dbabdd384973817bc26433c9c90ce755a9f7ec2627a949f65b" nocase ascii wide
                        $string11_VeamHax_offensive_tool_keyword = "67a426a646b50409aaaf70383a7f6b4b10981034623b4089a32fabb839997656" nocase ascii wide
                        $string12_VeamHax_offensive_tool_keyword = "A96C7C34-5791-43CF-9F8B-8EF5B3FB6EBA" nocase ascii wide
                        $string13_VeamHax_offensive_tool_keyword = "aaa6041912a6ba3cf167ecdb90a434a62feaf08639c59705847706b9f492015d" nocase ascii wide
                        $string14_VeamHax_offensive_tool_keyword = "f6888c1406e2b3549c9bc11929595170d3a74b0d4968f603cc33f9a896a53a95" nocase ascii wide
                        $string15_VeamHax_offensive_tool_keyword = "sfewer-r7/CVE-2023-27532" nocase ascii wide
                        $string16_VeamHax_offensive_tool_keyword = /VeeamHax_TemporaryKey\.pfx/ nocase ascii wide

    condition:
        any of them
}