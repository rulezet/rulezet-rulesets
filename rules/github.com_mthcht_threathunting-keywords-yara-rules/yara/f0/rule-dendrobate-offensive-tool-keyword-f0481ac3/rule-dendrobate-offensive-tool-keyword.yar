rule rule_Dendrobate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Dendrobate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dendrobate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Dendrobate_offensive_tool_keyword = /\sDendron\.exe/ nocase ascii wide
                        $string2_Dendrobate_offensive_tool_keyword = /\/Bates\.csproj/ nocase ascii wide
                        $string3_Dendrobate_offensive_tool_keyword = /\/Dendrobate\.git/ nocase ascii wide
                        $string4_Dendrobate_offensive_tool_keyword = /\/Dendron\.bin/ nocase ascii wide
                        $string5_Dendrobate_offensive_tool_keyword = /\/Dendron\.csproj/ nocase ascii wide
                        $string6_Dendrobate_offensive_tool_keyword = /\/Dendron\.exe/ nocase ascii wide
                        $string7_Dendrobate_offensive_tool_keyword = /\/Dendron\.sln/ nocase ascii wide
                        $string8_Dendrobate_offensive_tool_keyword = /\/hDendron\.cs/ nocase ascii wide
                        $string9_Dendrobate_offensive_tool_keyword = /\\Dendrobate\\/ nocase ascii wide
                        $string10_Dendrobate_offensive_tool_keyword = /\\Dendron\.bin/ nocase ascii wide
                        $string11_Dendrobate_offensive_tool_keyword = /\\Dendron\.exe/ nocase ascii wide
                        $string12_Dendrobate_offensive_tool_keyword = /\\Dendron\.sln/ nocase ascii wide
                        $string13_Dendrobate_offensive_tool_keyword = /Bates\.exe\s\-\-kill/ nocase ascii wide
                        $string14_Dendrobate_offensive_tool_keyword = /Bates\.exe\s\-\-listen/ nocase ascii wide
                        $string15_Dendrobate_offensive_tool_keyword = "Dendrobate-master" nocase ascii wide
                        $string16_Dendrobate_offensive_tool_keyword = /dendron.{0,1000}FileMonInject\.dll/ nocase ascii wide
                        $string17_Dendrobate_offensive_tool_keyword = /EasyHook\-Managed.{0,1000}InjectionLoader\.cs/ nocase ascii wide
                        $string18_Dendrobate_offensive_tool_keyword = /EasyHook\-Managed.{0,1000}WOW64Bypass\./ nocase ascii wide
                        $string19_Dendrobate_offensive_tool_keyword = /EasyHook\-Managed\/LocalHook\.cs/ nocase ascii wide
                        $string20_Dendrobate_offensive_tool_keyword = "FuzzySecurity/Dendrobate" nocase ascii wide
                        $string21_Dendrobate_offensive_tool_keyword = /ManagedEasyHook\.dll/ nocase ascii wide
                        $string22_Dendrobate_offensive_tool_keyword = /NativeEasyHook32\.dll/ nocase ascii wide
                        $string23_Dendrobate_offensive_tool_keyword = /NativeEasyHook64\.dll/ nocase ascii wide
                        $string24_Dendrobate_offensive_tool_keyword = "P8CuaPrgwBjunvZxJcgq" nocase ascii wide

    condition:
        any of them
}