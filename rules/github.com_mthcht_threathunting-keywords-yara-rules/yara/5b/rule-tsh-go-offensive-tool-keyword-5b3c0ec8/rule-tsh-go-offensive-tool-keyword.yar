rule rule_tsh_go_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tsh-go' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tsh-go"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_tsh_go_offensive_tool_keyword = "/tsh_linux_amd64"
                        $string2_tsh_go_offensive_tool_keyword = /\/tsh_windows_amd64\.exe/ nocase ascii wide
                        $string3_tsh_go_offensive_tool_keyword = /\/tshd\.go/
                        $string4_tsh_go_offensive_tool_keyword = "/tshd_linux_amd64"
                        $string5_tsh_go_offensive_tool_keyword = /\/tshd_windows\.go/ nocase ascii wide
                        $string6_tsh_go_offensive_tool_keyword = /\/tshd_windows_amd64\.exe/ nocase ascii wide
                        $string7_tsh_go_offensive_tool_keyword = /\/tsh\-go\.git/ nocase ascii wide
                        $string8_tsh_go_offensive_tool_keyword = /\\tsh_windows_amd64\.exe/ nocase ascii wide
                        $string9_tsh_go_offensive_tool_keyword = /\\tshd\.go/ nocase ascii wide
                        $string10_tsh_go_offensive_tool_keyword = /\\tshd_windows\.go/ nocase ascii wide
                        $string11_tsh_go_offensive_tool_keyword = /\\tshd_windows_amd64\.exe/ nocase ascii wide
                        $string12_tsh_go_offensive_tool_keyword = "1647b6e9073cee9751e3cd9a031656a6b830355a7a87d15cdc18601ddfa2f327" nocase ascii wide
                        $string13_tsh_go_offensive_tool_keyword = "32d12ed0ff8db1c95d1ee507561ee0db4c36200277a2bc4cd1b643e385ff5ebe" nocase ascii wide
                        $string14_tsh_go_offensive_tool_keyword = "6c78751a2dd30be8fcb962a93ab912d335a56a7a722dc502bf55eb4c2c7e7c8e" nocase ascii wide
                        $string15_tsh_go_offensive_tool_keyword = "8822c7fa386065eace366042536dcbc277a5be58efae8ce02bf9e4c583e07918" nocase ascii wide
                        $string16_tsh_go_offensive_tool_keyword = "c9bdad45179ca59d8b6b725d329b8ab1ba8e1561c44cc3a14093bfe3c97df3ae" nocase ascii wide
                        $string17_tsh_go_offensive_tool_keyword = /cmd\/tsh\.go/ nocase ascii wide
                        $string18_tsh_go_offensive_tool_keyword = /cmd\/tshd\.go/ nocase ascii wide
                        $string19_tsh_go_offensive_tool_keyword = "CykuTW/tsh-go" nocase ascii wide
                        $string20_tsh_go_offensive_tool_keyword = "tsh_linux_amd64 "
                        $string21_tsh_go_offensive_tool_keyword = "tshd_linux_amd64 "
                        $string22_tsh_go_offensive_tool_keyword = /tshd_windows_amd64\.exe\s/ nocase ascii wide

    condition:
        any of them
}