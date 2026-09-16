rule rule_SharpAzbelt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpAzbelt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAzbelt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpAzbelt_offensive_tool_keyword = /\/SharpAzbelt\.git/ nocase ascii wide
                        $string2_SharpAzbelt_offensive_tool_keyword = /\[\!\]\s\s\s\sFailed\sto\senumerate\sCredman\:/ nocase ascii wide
                        $string3_SharpAzbelt_offensive_tool_keyword = /\[i\]\sAAD\sJoin\:.{0,1000}enumerate/ nocase ascii wide
                        $string4_SharpAzbelt_offensive_tool_keyword = /\[i\]\sCredman\:.{0,1000}Credential\sBlob\sDecrypted/ nocase ascii wide
                        $string5_SharpAzbelt_offensive_tool_keyword = /\\SharpAzbelt\.csproj/ nocase ascii wide
                        $string6_SharpAzbelt_offensive_tool_keyword = /\\SharpAzbelt\.exe/ nocase ascii wide
                        $string7_SharpAzbelt_offensive_tool_keyword = /\\SharpAzbelt\.sln/ nocase ascii wide
                        $string8_SharpAzbelt_offensive_tool_keyword = "57D4D4F4-F083-47A3-AE33-AE2500ABA3B6" nocase ascii wide
                        $string9_SharpAzbelt_offensive_tool_keyword = /ParseMSALCache.{0,1000}\.azure\\msal_token_cache\.bin/ nocase ascii wide
                        $string10_SharpAzbelt_offensive_tool_keyword = /ParseMSALCache.{0,1000}Appdata\\Local\\\.IdentityService\\msal\.cache/ nocase ascii wide
                        $string11_SharpAzbelt_offensive_tool_keyword = "redskal/SharpAzbelt" nocase ascii wide
                        $string12_SharpAzbelt_offensive_tool_keyword = "SharpAzbelt-main" nocase ascii wide

    condition:
        any of them
}