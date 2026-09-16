rule rule_SharpWeb_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpWeb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpWeb"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpWeb_offensive_tool_keyword = /\.exe\s\-b\schromium\s\-p\s.{0,1000}\\AppData\\Local\\Google\\Chrome\\/ nocase ascii wide
                        $string2_SharpWeb_offensive_tool_keyword = /\/SharpWeb\.exe/ nocase ascii wide
                        $string3_SharpWeb_offensive_tool_keyword = /\/SharpWeb\.git/ nocase ascii wide
                        $string4_SharpWeb_offensive_tool_keyword = /\\SharpWeb\.exe/ nocase ascii wide
                        $string5_SharpWeb_offensive_tool_keyword = /\\SharpWeb\.sln/ nocase ascii wide
                        $string6_SharpWeb_offensive_tool_keyword = ">SharpWeb<" nocase ascii wide
                        $string7_SharpWeb_offensive_tool_keyword = "1c309b473a4221fa7bbb5566935f888a7d8cf523ea33c6f7b568c7342f81419a" nocase ascii wide
                        $string8_SharpWeb_offensive_tool_keyword = "1e2744c89803f6afc884b214ba4a8f47dfc1725a4180d767630205feeead064b" nocase ascii wide
                        $string9_SharpWeb_offensive_tool_keyword = "91292bac-72b4-4aab-9e5f-2bc1843c8ea3" nocase ascii wide
                        $string10_SharpWeb_offensive_tool_keyword = "99292BAC-72B4-4AAB-9E5F-2BC1843C8EA3" nocase ascii wide
                        $string11_SharpWeb_offensive_tool_keyword = "AE844C23-294E-4690-8CF3-2E5F9769D8E0" nocase ascii wide
                        $string12_SharpWeb_offensive_tool_keyword = /decrypt_chrome_v20_cookie\.py/ nocase ascii wide
                        $string13_SharpWeb_offensive_tool_keyword = /SharpWeb\.exe\s\-/ nocase ascii wide
                        $string14_SharpWeb_offensive_tool_keyword = "StarfireLab/SharpWeb" nocase ascii wide
                        $string15_SharpWeb_offensive_tool_keyword = "sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=" nocase ascii wide
                        $string16_SharpWeb_offensive_tool_keyword = /vaultSchema\.Add\(new\sGuid\(\\"\\"4BF4C442\-9B8A\-41A0\-B380\-DD4A704DDB28\\"\\"/ nocase ascii wide

    condition:
        any of them
}