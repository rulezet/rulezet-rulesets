rule VeamHax
{
    meta:
        description = "Detection patterns for the tool 'VeamHax' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VeamHax"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-sql\s\\"EXEC\smaster\.\.xp_cmdshell/ nocase ascii wide
                        $string2 = " --sql \"EXEC sp_configure 'xp_cmdshell'" nocase ascii wide
                        $string3 = " --sql \"EXEC sp_configure 'xp_cmdshell', '1'" nocase ascii wide
                        $string4 = /\sVeeamHax\.exe/ nocase ascii wide
                        $string5 = /\/VeeamHax\.exe/ nocase ascii wide
                        $string6 = /\\VeeamHax\.exe/ nocase ascii wide
                        $string7 = /\\VeeamHax\.pdb/ nocase ascii wide
                        $string8 = /\\VeeamHax\.sln/ nocase ascii wide
                        $string9 = "2ffb7bfe8f888c083361a65e7a8a349ba1f6b16971522011f545029fb20b3fd1" nocase ascii wide
                        $string10 = "59c2e7b63bbfe6dbabdd384973817bc26433c9c90ce755a9f7ec2627a949f65b" nocase ascii wide
                        $string11 = "67a426a646b50409aaaf70383a7f6b4b10981034623b4089a32fabb839997656" nocase ascii wide
                        $string12 = "A96C7C34-5791-43CF-9F8B-8EF5B3FB6EBA" nocase ascii wide
                        $string13 = "aaa6041912a6ba3cf167ecdb90a434a62feaf08639c59705847706b9f492015d" nocase ascii wide
                        $string14 = "f6888c1406e2b3549c9bc11929595170d3a74b0d4968f603cc33f9a896a53a95" nocase ascii wide
                        $string15 = "sfewer-r7/CVE-2023-27532" nocase ascii wide
                        $string16 = /VeeamHax_TemporaryKey\.pfx/ nocase ascii wide

    condition:
        any of them
}