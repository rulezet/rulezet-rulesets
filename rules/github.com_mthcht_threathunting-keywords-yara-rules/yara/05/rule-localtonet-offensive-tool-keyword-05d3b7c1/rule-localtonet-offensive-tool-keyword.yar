rule rule_localtonet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'localtonet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtonet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_localtonet_offensive_tool_keyword = /\slocaltonet\.service/ nocase ascii wide
                        $string2_localtonet_offensive_tool_keyword = /\/localtonet\.dll/ nocase ascii wide
                        $string3_localtonet_offensive_tool_keyword = /\/localtonet\.exe/ nocase ascii wide
                        $string4_localtonet_offensive_tool_keyword = /\/localtonet\.git/ nocase ascii wide
                        $string5_localtonet_offensive_tool_keyword = /\/localtonet\.service/
                        $string6_localtonet_offensive_tool_keyword = "/localtonet-win" nocase ascii wide
                        $string7_localtonet_offensive_tool_keyword = "/opt/localtonet"
                        $string8_localtonet_offensive_tool_keyword = /\\localtonet\.dll/ nocase ascii wide
                        $string9_localtonet_offensive_tool_keyword = /\\localtonet\.exe/ nocase ascii wide
                        $string10_localtonet_offensive_tool_keyword = /\\localtonet\-win/ nocase ascii wide
                        $string11_localtonet_offensive_tool_keyword = "925fe97c66e61207fec6e73bf01385139ccf6a482c234cb63f1bfafa6b260cb7" nocase ascii wide
                        $string12_localtonet_offensive_tool_keyword = "a82ec4a7feac8a7bcab876286599e1df136c93ac470ba634fa77be156ee40615" nocase ascii wide
                        $string13_localtonet_offensive_tool_keyword = /\-e\slocaltonet\.service/ nocase ascii wide
                        $string14_localtonet_offensive_tool_keyword = "e27bbd5323fd6e3c1fcd501bf9279dd83fa211892c10ebf552773f4f5c89e4ab" nocase ascii wide
                        $string15_localtonet_offensive_tool_keyword = "engineseller/localtonet" nocase ascii wide
                        $string16_localtonet_offensive_tool_keyword = /localtonet\.com\/download\// nocase ascii wide
                        $string17_localtonet_offensive_tool_keyword = /queue\.localtonet\.com/ nocase ascii wide
                        $string18_localtonet_offensive_tool_keyword = /seq\.localtonet\.com\/api/ nocase ascii wide

    condition:
        any of them
}