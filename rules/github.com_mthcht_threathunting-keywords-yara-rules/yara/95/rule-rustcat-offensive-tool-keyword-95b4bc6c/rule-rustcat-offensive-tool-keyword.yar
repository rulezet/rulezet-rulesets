rule rule_rustcat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rustcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rustcat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rustcat_offensive_tool_keyword = /\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'/
                        $string2_rustcat_offensive_tool_keyword = /\/rcat\-v.{0,1000}\-win\-x86_64\.exe/ nocase ascii wide
                        $string3_rustcat_offensive_tool_keyword = "/rustcat/releases/latest/download/" nocase ascii wide
                        $string4_rustcat_offensive_tool_keyword = /\/src\/unixshell\.rs/ nocase ascii wide
                        $string5_rustcat_offensive_tool_keyword = /\\rcat\-v.{0,1000}\-win\-x86_64\.exe/ nocase ascii wide
                        $string6_rustcat_offensive_tool_keyword = "B473B9A4135DE247C6D76510B40F63F8F1E5A2AB" nocase ascii wide
                        $string7_rustcat_offensive_tool_keyword = "blackarch/tree/master/packages/rustcat" nocase ascii wide
                        $string8_rustcat_offensive_tool_keyword = "pacman -S rustcat" nocase ascii wide
                        $string9_rustcat_offensive_tool_keyword = "rcan listen -ib " nocase ascii wide
                        $string10_rustcat_offensive_tool_keyword = "rcat c -s bash "
                        $string11_rustcat_offensive_tool_keyword = "rcat connect -s bash"
                        $string12_rustcat_offensive_tool_keyword = "rcat listen 55660" nocase ascii wide
                        $string13_rustcat_offensive_tool_keyword = "rcat listen -ie " nocase ascii wide
                        $string14_rustcat_offensive_tool_keyword = "rcat listen -l " nocase ascii wide
                        $string15_rustcat_offensive_tool_keyword = /rcat\-v3\..{0,1000}darwin\-aarch64/
                        $string16_rustcat_offensive_tool_keyword = /rcat\-v3\..{0,1000}\-darwin\-x86_64/
                        $string17_rustcat_offensive_tool_keyword = /rcat\-v3\..{0,1000}\-linux\-x86_64/
                        $string18_rustcat_offensive_tool_keyword = /rustcat\-3\.0\.0\.zip/ nocase ascii wide
                        $string19_rustcat_offensive_tool_keyword = "rcat listen " nocase ascii wide

    condition:
        any of them
}