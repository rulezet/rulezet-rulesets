rule rule_AdaptixC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AdaptixC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AdaptixC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AdaptixC2_offensive_tool_keyword = /\/AdapticClient\.exe/ nocase ascii wide
                        $string2_AdaptixC2_offensive_tool_keyword = /\/AdaptixC2\.git/ nocase ascii wide
                        $string3_AdaptixC2_offensive_tool_keyword = /\\AdapticClient\.exe/ nocase ascii wide
                        $string4_AdaptixC2_offensive_tool_keyword = "9117d2d155a124e050aaf1c64011f5a65198f9dd91289ffcf809f8364740f1d5" nocase ascii wide
                        $string5_AdaptixC2_offensive_tool_keyword = "99a5f42e-60a8-4f1e-9dff-35443b972707" nocase ascii wide
                        $string6_AdaptixC2_offensive_tool_keyword = "AdaptixClient/AdaptixClient" nocase ascii wide
                        $string7_AdaptixC2_offensive_tool_keyword = "Adaptix-Framework/AdaptixC2" nocase ascii wide
                        $string8_AdaptixC2_offensive_tool_keyword = "AdaptixServer -p" nocase ascii wide
                        $string9_AdaptixC2_offensive_tool_keyword = "AdaptixServer/adaptixserver" nocase ascii wide
                        $string10_AdaptixC2_offensive_tool_keyword = "d886eb849d99a52449eb869bdf954644c2d5259db29be9cc757084bf166c42e0" nocase ascii wide
                        $string11_AdaptixC2_offensive_tool_keyword = /https\:\/\/adaptix\-framework\.gitbook\.io\/adaptix\-framework\/adaptix\-c2\/getting\-starting\// nocase ascii wide

    condition:
        any of them
}