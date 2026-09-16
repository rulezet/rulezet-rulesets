rule rule_PrivKit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PrivKit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivKit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PrivKit_offensive_tool_keyword = /\/PrivKit\.git/ nocase ascii wide
                        $string2_PrivKit_offensive_tool_keyword = "/PrivKit/" nocase ascii wide
                        $string3_PrivKit_offensive_tool_keyword = /\\modifiableautorun\.o/ nocase ascii wide
                        $string4_PrivKit_offensive_tool_keyword = /\\PrivKit\\/ nocase ascii wide
                        $string5_PrivKit_offensive_tool_keyword = /\\tokenprivileges\.c/ nocase ascii wide
                        $string6_PrivKit_offensive_tool_keyword = /\\tokenprivileges\.o/ nocase ascii wide
                        $string7_PrivKit_offensive_tool_keyword = /\\unquotedsvcpath\.o/ nocase ascii wide
                        $string8_PrivKit_offensive_tool_keyword = /alwaysinstallelevated\.c/ nocase ascii wide
                        $string9_PrivKit_offensive_tool_keyword = /alwaysinstallelevated\.o/ nocase ascii wide
                        $string10_PrivKit_offensive_tool_keyword = /\-c\scredentialmanager\.c\s\-o\scredentialmanager\.o/ nocase ascii wide
                        $string11_PrivKit_offensive_tool_keyword = /\-c\smodifiableautorun\.c\s\-o\smodifiableautorun\.o/ nocase ascii wide
                        $string12_PrivKit_offensive_tool_keyword = /\-c\stokenprivileges\.c\s\-o\stokenprivileges\.o/ nocase ascii wide
                        $string13_PrivKit_offensive_tool_keyword = /\-c\sunquotedsvcpath\.c\s\-o\sunquotedsvcpath\.o/ nocase ascii wide
                        $string14_PrivKit_offensive_tool_keyword = /hijackablepath\.c/ nocase ascii wide
                        $string15_PrivKit_offensive_tool_keyword = /hijackablepath\.o/ nocase ascii wide
                        $string16_PrivKit_offensive_tool_keyword = /inline\-execute\s.{0,1000}tokenprivileges\.o/ nocase ascii wide
                        $string17_PrivKit_offensive_tool_keyword = "Priv Esc Check Bof" nocase ascii wide
                        $string18_PrivKit_offensive_tool_keyword = /privcheck\.cna/ nocase ascii wide
                        $string19_PrivKit_offensive_tool_keyword = "privcheck32" nocase ascii wide
                        $string20_PrivKit_offensive_tool_keyword = "PrivKit32" nocase ascii wide
                        $string21_PrivKit_offensive_tool_keyword = "PrivKit-main" nocase ascii wide

    condition:
        any of them
}