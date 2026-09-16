rule rule_SharpSSDP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSSDP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSSDP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSSDP_offensive_tool_keyword = /\/SharpSSDP\.git/ nocase ascii wide
                        $string2_SharpSSDP_offensive_tool_keyword = "/SharpSSDP/" nocase ascii wide
                        $string3_SharpSSDP_offensive_tool_keyword = /\\SharpSSDP\.csproj/ nocase ascii wide
                        $string4_SharpSSDP_offensive_tool_keyword = /\\SharpSSDP\.sln/ nocase ascii wide
                        $string5_SharpSSDP_offensive_tool_keyword = /\\SharpSSDP\\/ nocase ascii wide
                        $string6_SharpSSDP_offensive_tool_keyword = "2c03dc7ed9a0770af9e8ba9c8fffa0e8b8ffcdf1f7efe5d2d33a32fe736989cd" nocase ascii wide
                        $string7_SharpSSDP_offensive_tool_keyword = "583409661e2afdf55553b7da2e510aef9cd10c542d98ebc4ee1962d1d4472bc1" nocase ascii wide
                        $string8_SharpSSDP_offensive_tool_keyword = "6E383DE4-DE89-4247-A41A-79DB1DC03AAA" nocase ascii wide
                        $string9_SharpSSDP_offensive_tool_keyword = "cddd9cbec4525bc73c44a2c154b12372210e9ccedb9cafd7c495a590c481f6a8" nocase ascii wide
                        $string10_SharpSSDP_offensive_tool_keyword = "namespace SharpSSDP" nocase ascii wide
                        $string11_SharpSSDP_offensive_tool_keyword = "rvrsh3ll/SharpSSDP" nocase ascii wide
                        $string12_SharpSSDP_offensive_tool_keyword = /SharpSSDP\.exe/ nocase ascii wide

    condition:
        any of them
}