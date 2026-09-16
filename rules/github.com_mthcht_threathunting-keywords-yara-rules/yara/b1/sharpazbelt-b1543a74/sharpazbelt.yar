rule SharpAzbelt
{
    meta:
        description = "Detection patterns for the tool 'SharpAzbelt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAzbelt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpAzbelt\.git/ nocase ascii wide
                        $string2 = /\[\!\]\s\s\s\sFailed\sto\senumerate\sCredman\:/ nocase ascii wide
                        $string3 = /\[i\]\sAAD\sJoin\:.{0,1000}enumerate/ nocase ascii wide
                        $string4 = /\[i\]\sCredman\:.{0,1000}Credential\sBlob\sDecrypted/ nocase ascii wide
                        $string5 = /\\SharpAzbelt\.csproj/ nocase ascii wide
                        $string6 = /\\SharpAzbelt\.exe/ nocase ascii wide
                        $string7 = /\\SharpAzbelt\.sln/ nocase ascii wide
                        $string8 = "57D4D4F4-F083-47A3-AE33-AE2500ABA3B6" nocase ascii wide
                        $string9 = /ParseMSALCache.{0,1000}\.azure\\msal_token_cache\.bin/ nocase ascii wide
                        $string10 = /ParseMSALCache.{0,1000}Appdata\\Local\\\.IdentityService\\msal\.cache/ nocase ascii wide
                        $string11 = "redskal/SharpAzbelt" nocase ascii wide
                        $string12 = "SharpAzbelt-main" nocase ascii wide

    condition:
        any of them
}