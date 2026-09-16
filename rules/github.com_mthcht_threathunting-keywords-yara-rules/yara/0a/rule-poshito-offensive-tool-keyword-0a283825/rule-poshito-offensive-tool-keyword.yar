rule rule_Poshito_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Poshito' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Poshito"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Poshito_offensive_tool_keyword = "/Poshito -w /Poshito/Poshito poshito" nocase ascii wide
                        $string2_Poshito_offensive_tool_keyword = /\/Poshito\.dll/ nocase ascii wide
                        $string3_Poshito_offensive_tool_keyword = /\/Poshito\.exe/ nocase ascii wide
                        $string4_Poshito_offensive_tool_keyword = /\/Poshito\.git/ nocase ascii wide
                        $string5_Poshito_offensive_tool_keyword = "/Poshito/Poshito/Agent"
                        $string6_Poshito_offensive_tool_keyword = /\/PowerShdll\.exe/ nocase ascii wide
                        $string7_Poshito_offensive_tool_keyword = /\[\+\]\sUPXed\ssuccessfully/ nocase ascii wide
                        $string8_Poshito_offensive_tool_keyword = /\\patch_exit\.exe/ nocase ascii wide
                        $string9_Poshito_offensive_tool_keyword = /\\Poshito\.dll/ nocase ascii wide
                        $string10_Poshito_offensive_tool_keyword = /\\Poshito\.exe/ nocase ascii wide
                        $string11_Poshito_offensive_tool_keyword = /\\PowerShdll\.exe/ nocase ascii wide
                        $string12_Poshito_offensive_tool_keyword = ">PowerShdll<" nocase ascii wide
                        $string13_Poshito_offensive_tool_keyword = "a5d8564157388d8d628ba9b8785307fd8cbbf3b6fafc1cd46160712a0015ced6" nocase ascii wide
                        $string14_Poshito_offensive_tool_keyword = "d9fb91ea8b177ea86eefc1a62a875e55136fa268aa762fa44a377023f89b7673" nocase ascii wide
                        $string15_Poshito_offensive_tool_keyword = "da84dfd9b5b5f068189c1a37f2f3003c402ebf6bc1080e70caa82c51ee4c2bc8" nocase ascii wide
                        $string16_Poshito_offensive_tool_keyword = "docker build -t poshito" nocase ascii wide
                        $string17_Poshito_offensive_tool_keyword = /go\sinstall\smvdan\.cc\/garble\@latest/ nocase ascii wide
                        $string18_Poshito_offensive_tool_keyword = "itaymigdal/Poshito" nocase ascii wide
                        $string19_Poshito_offensive_tool_keyword = /Password\sconfirmed\.\s\\nPoshito\sis\swelcoming\syou/ nocase ascii wide
                        $string20_Poshito_offensive_tool_keyword = "Poshito-C2 agent builder" nocase ascii wide

    condition:
        any of them
}