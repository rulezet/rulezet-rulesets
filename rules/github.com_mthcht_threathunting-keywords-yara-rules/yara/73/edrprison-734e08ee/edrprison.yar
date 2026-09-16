rule EDRPrison
{
    meta:
        description = "Detection patterns for the tool 'EDRPrison' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRPrison"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/EDRPrison\.git/ nocase ascii wide
                        $string2 = /\\EDRPrison\.csproj/ nocase ascii wide
                        $string3 = /\\EDRPrison\-main/ nocase ascii wide
                        $string4 = "036fedcd8c1d30e41ad0f36aa87f90338b7d1310632c729706d918a34d398eb5" nocase ascii wide
                        $string5 = "1cbb36d4cf2b775b3009d1d33ce8a90c8a321cc30b884250639142cea085ac06" nocase ascii wide
                        $string6 = "9674DF71-0814-4398-8A77-5A32A8CBE61E" nocase ascii wide
                        $string7 = "senzee1984/EDRPrison" nocase ascii wide

    condition:
        any of them
}