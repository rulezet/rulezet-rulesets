rule tsh_go
{
    meta:
        description = "Detection patterns for the tool 'tsh-go' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tsh-go"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/tsh_linux_amd64"
                        $string2 = /\/tsh_windows_amd64\.exe/ nocase ascii wide
                        $string3 = /\/tshd\.go/
                        $string4 = "/tshd_linux_amd64"
                        $string5 = /\/tshd_windows\.go/ nocase ascii wide
                        $string6 = /\/tshd_windows_amd64\.exe/ nocase ascii wide
                        $string7 = /\/tsh\-go\.git/ nocase ascii wide
                        $string8 = /\\tsh_windows_amd64\.exe/ nocase ascii wide
                        $string9 = /\\tshd\.go/ nocase ascii wide
                        $string10 = /\\tshd_windows\.go/ nocase ascii wide
                        $string11 = /\\tshd_windows_amd64\.exe/ nocase ascii wide
                        $string12 = "1647b6e9073cee9751e3cd9a031656a6b830355a7a87d15cdc18601ddfa2f327" nocase ascii wide
                        $string13 = "32d12ed0ff8db1c95d1ee507561ee0db4c36200277a2bc4cd1b643e385ff5ebe" nocase ascii wide
                        $string14 = "6c78751a2dd30be8fcb962a93ab912d335a56a7a722dc502bf55eb4c2c7e7c8e" nocase ascii wide
                        $string15 = "8822c7fa386065eace366042536dcbc277a5be58efae8ce02bf9e4c583e07918" nocase ascii wide
                        $string16 = "c9bdad45179ca59d8b6b725d329b8ab1ba8e1561c44cc3a14093bfe3c97df3ae" nocase ascii wide
                        $string17 = /cmd\/tsh\.go/ nocase ascii wide
                        $string18 = /cmd\/tshd\.go/ nocase ascii wide
                        $string19 = "CykuTW/tsh-go" nocase ascii wide
                        $string20 = "tsh_linux_amd64 "
                        $string21 = "tshd_linux_amd64 "
                        $string22 = /tshd_windows_amd64\.exe\s/ nocase ascii wide

    condition:
        any of them
}