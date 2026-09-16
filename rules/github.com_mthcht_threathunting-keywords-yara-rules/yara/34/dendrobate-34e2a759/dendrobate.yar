rule Dendrobate
{
    meta:
        description = "Detection patterns for the tool 'Dendrobate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dendrobate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sDendron\.exe/ nocase ascii wide
                        $string2 = /\/Bates\.csproj/ nocase ascii wide
                        $string3 = /\/Dendrobate\.git/ nocase ascii wide
                        $string4 = /\/Dendron\.bin/ nocase ascii wide
                        $string5 = /\/Dendron\.csproj/ nocase ascii wide
                        $string6 = /\/Dendron\.exe/ nocase ascii wide
                        $string7 = /\/Dendron\.sln/ nocase ascii wide
                        $string8 = /\/hDendron\.cs/ nocase ascii wide
                        $string9 = /\\Dendrobate\\/ nocase ascii wide
                        $string10 = /\\Dendron\.bin/ nocase ascii wide
                        $string11 = /\\Dendron\.exe/ nocase ascii wide
                        $string12 = /\\Dendron\.sln/ nocase ascii wide
                        $string13 = /Bates\.exe\s\-\-kill/ nocase ascii wide
                        $string14 = /Bates\.exe\s\-\-listen/ nocase ascii wide
                        $string15 = "Dendrobate-master" nocase ascii wide
                        $string16 = /dendron.{0,1000}FileMonInject\.dll/ nocase ascii wide
                        $string17 = /EasyHook\-Managed.{0,1000}InjectionLoader\.cs/ nocase ascii wide
                        $string18 = /EasyHook\-Managed.{0,1000}WOW64Bypass\./ nocase ascii wide
                        $string19 = /EasyHook\-Managed\/LocalHook\.cs/ nocase ascii wide
                        $string20 = "FuzzySecurity/Dendrobate" nocase ascii wide
                        $string21 = /ManagedEasyHook\.dll/ nocase ascii wide
                        $string22 = /NativeEasyHook32\.dll/ nocase ascii wide
                        $string23 = /NativeEasyHook64\.dll/ nocase ascii wide
                        $string24 = "P8CuaPrgwBjunvZxJcgq" nocase ascii wide

    condition:
        any of them
}