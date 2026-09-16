rule stunnel
{
    meta:
        description = "Detection patterns for the tool 'stunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\srsync\.stunnel\.org\:\:stunnel\s/ nocase ascii wide
                        $string2 = /\/stunnel\-.{0,1000}\.tar\.gz/
                        $string3 = /\/stunnel\-latest\.tar\.gz/ nocase ascii wide
                        $string4 = /\/stunnel\-latest\-android\.zip/ nocase ascii wide
                        $string5 = /\/stunnel\-latest\-win64\-installer\.exe/ nocase ascii wide
                        $string6 = "/tmp/stunnel"
                        $string7 = /\\CurrentVersion\\Uninstall\\stunnel/ nocase ascii wide
                        $string8 = /\\Program\sFiles\s\(x86\)\\stunnel\\/ nocase ascii wide
                        $string9 = /\\SOFTWARE\\WOW6432Node\\NSIS_stunnel\\/ nocase ascii wide
                        $string10 = /\\stunnel\-.{0,1000}\-win64\-installer\.exe/ nocase ascii wide
                        $string11 = /\\stunnel\\config\\stunnel\.pem/ nocase ascii wide
                        $string12 = /\\stunnel\-latest\-win64\-installer\.exe/ nocase ascii wide
                        $string13 = /\\tstunnel\.exe/ nocase ascii wide
                        $string14 = "719e6b5eedc0d4b178d6f0f999555fc3292a22747f3ed2238d529604ee1a5532" nocase ascii wide
                        $string15 = "bc917c3bcd943a4d632360c067977a31e85e385f5f4845f69749bce88183cb38" nocase ascii wide
                        $string16 = "d686b1a4135947718e7a8157a8cb6694ed50e2267713de1972941148a8859789" nocase ascii wide

    condition:
        any of them
}