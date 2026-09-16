rule PrivKit
{
    meta:
        description = "Detection patterns for the tool 'PrivKit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivKit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PrivKit\.git/ nocase ascii wide
                        $string2 = "/PrivKit/" nocase ascii wide
                        $string3 = /\\modifiableautorun\.o/ nocase ascii wide
                        $string4 = /\\PrivKit\\/ nocase ascii wide
                        $string5 = /\\tokenprivileges\.c/ nocase ascii wide
                        $string6 = /\\tokenprivileges\.o/ nocase ascii wide
                        $string7 = /\\unquotedsvcpath\.o/ nocase ascii wide
                        $string8 = /alwaysinstallelevated\.c/ nocase ascii wide
                        $string9 = /alwaysinstallelevated\.o/ nocase ascii wide
                        $string10 = /\-c\scredentialmanager\.c\s\-o\scredentialmanager\.o/ nocase ascii wide
                        $string11 = /\-c\smodifiableautorun\.c\s\-o\smodifiableautorun\.o/ nocase ascii wide
                        $string12 = /\-c\stokenprivileges\.c\s\-o\stokenprivileges\.o/ nocase ascii wide
                        $string13 = /\-c\sunquotedsvcpath\.c\s\-o\sunquotedsvcpath\.o/ nocase ascii wide
                        $string14 = /hijackablepath\.c/ nocase ascii wide
                        $string15 = /hijackablepath\.o/ nocase ascii wide
                        $string16 = /inline\-execute\s.{0,1000}tokenprivileges\.o/ nocase ascii wide
                        $string17 = "Priv Esc Check Bof" nocase ascii wide
                        $string18 = /privcheck\.cna/ nocase ascii wide
                        $string19 = "privcheck32" nocase ascii wide
                        $string20 = "PrivKit32" nocase ascii wide
                        $string21 = "PrivKit-main" nocase ascii wide

    condition:
        any of them
}