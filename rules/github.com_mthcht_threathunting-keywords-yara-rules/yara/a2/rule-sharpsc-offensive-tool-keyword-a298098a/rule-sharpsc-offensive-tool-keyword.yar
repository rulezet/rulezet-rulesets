rule rule_SharpSC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSC_offensive_tool_keyword = /\.exe\saction\=create\s.{0,1000}\sservice\=.{0,1000}\sdisplayname\=.{0,1000}\sbinpath\=/ nocase ascii wide
                        $string2_SharpSC_offensive_tool_keyword = /\/SharpSC\.exe/ nocase ascii wide
                        $string3_SharpSC_offensive_tool_keyword = /\/SharpSC\.git/ nocase ascii wide
                        $string4_SharpSC_offensive_tool_keyword = /\\SharpSC\.exe/ nocase ascii wide
                        $string5_SharpSC_offensive_tool_keyword = /\\SharpSC\-main/ nocase ascii wide
                        $string6_SharpSC_offensive_tool_keyword = "3b6a44069c343b15c9bafec9feb7d5597f936485c68f29316e96fe97aa15d06d" nocase ascii wide
                        $string7_SharpSC_offensive_tool_keyword = "3D9D679D-6052-4C5E-BD91-2BC3DED09D0A" nocase ascii wide
                        $string8_SharpSC_offensive_tool_keyword = "4c0fdf591ecec6aaeb3b6529f7b3800125910f16bc23496ba279a4bee0c2361c" nocase ascii wide
                        $string9_SharpSC_offensive_tool_keyword = "9870daa238c3cab7fa949a1f8b80d3451c78eb07d18030ad061d8b91d612decc" nocase ascii wide
                        $string10_SharpSC_offensive_tool_keyword = "djhohnstein/SharpSC" nocase ascii wide
                        $string11_SharpSC_offensive_tool_keyword = "namespace SharpSC" nocase ascii wide

    condition:
        any of them
}