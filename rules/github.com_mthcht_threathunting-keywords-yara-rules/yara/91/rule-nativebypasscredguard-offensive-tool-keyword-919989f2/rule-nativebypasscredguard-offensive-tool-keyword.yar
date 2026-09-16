rule rule_NativeBypassCredGuard_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NativeBypassCredGuard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NativeBypassCredGuard"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NativeBypassCredGuard_offensive_tool_keyword = /\/NativeBypassCredGuard\.git/ nocase ascii wide
                        $string2_NativeBypassCredGuard_offensive_tool_keyword = /\[\+\]\sEnable\sSeDebugPrivilege\:\s\\tOK/ nocase ascii wide
                        $string3_NativeBypassCredGuard_offensive_tool_keyword = /\\NativeBypassCredGuard\.sln/ nocase ascii wide
                        $string4_NativeBypassCredGuard_offensive_tool_keyword = /\\NativeBypassCredGuard_C\+\+/ nocase ascii wide
                        $string5_NativeBypassCredGuard_offensive_tool_keyword = /\\NativeBypassCredGuard\-main/ nocase ascii wide
                        $string6_NativeBypassCredGuard_offensive_tool_keyword = "0614ec0ae3a38dd774d2e03dfeb05bad8e2c573f1943ab951c6129825bde4df8" nocase ascii wide
                        $string7_NativeBypassCredGuard_offensive_tool_keyword = "1d294d6fcae8b9d57d60166f102fd91d63ad88def2ab80eadcac22750f6f3c47" nocase ascii wide
                        $string8_NativeBypassCredGuard_offensive_tool_keyword = "28bba6f4d8a170a77e383fe09fcc3d5258496fb45b0c226891cc51f8b96ef489" nocase ascii wide
                        $string9_NativeBypassCredGuard_offensive_tool_keyword = "c4d31433-5017-4b5e-956b-8a540520986c" nocase ascii wide
                        $string10_NativeBypassCredGuard_offensive_tool_keyword = "E383DFEA-EC22-4667-9434-3F2591A03740" nocase ascii wide
                        $string11_NativeBypassCredGuard_offensive_tool_keyword = /NativeBypassCredGuard\.exe/ nocase ascii wide
                        $string12_NativeBypassCredGuard_offensive_tool_keyword = "ricardojoserf/NativeBypassCredGuard" nocase ascii wide

    condition:
        any of them
}