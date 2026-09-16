rule rule_stunnel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'stunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_stunnel_greyware_tool_keyword = /\srsync\.stunnel\.org\:\:stunnel\s/ nocase ascii wide
                        $string2_stunnel_greyware_tool_keyword = /\/stunnel\-.{0,1000}\.tar\.gz/
                        $string3_stunnel_greyware_tool_keyword = /\/stunnel\-latest\.tar\.gz/ nocase ascii wide
                        $string4_stunnel_greyware_tool_keyword = /\/stunnel\-latest\-android\.zip/ nocase ascii wide
                        $string5_stunnel_greyware_tool_keyword = /\/stunnel\-latest\-win64\-installer\.exe/ nocase ascii wide
                        $string6_stunnel_greyware_tool_keyword = "/tmp/stunnel"
                        $string7_stunnel_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\stunnel/ nocase ascii wide
                        $string8_stunnel_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\stunnel\\/ nocase ascii wide
                        $string9_stunnel_greyware_tool_keyword = /\\SOFTWARE\\WOW6432Node\\NSIS_stunnel\\/ nocase ascii wide
                        $string10_stunnel_greyware_tool_keyword = /\\stunnel\-.{0,1000}\-win64\-installer\.exe/ nocase ascii wide
                        $string11_stunnel_greyware_tool_keyword = /\\stunnel\\config\\stunnel\.pem/ nocase ascii wide
                        $string12_stunnel_greyware_tool_keyword = /\\stunnel\-latest\-win64\-installer\.exe/ nocase ascii wide
                        $string13_stunnel_greyware_tool_keyword = /\\tstunnel\.exe/ nocase ascii wide
                        $string14_stunnel_greyware_tool_keyword = "719e6b5eedc0d4b178d6f0f999555fc3292a22747f3ed2238d529604ee1a5532" nocase ascii wide
                        $string15_stunnel_greyware_tool_keyword = "bc917c3bcd943a4d632360c067977a31e85e385f5f4845f69749bce88183cb38" nocase ascii wide
                        $string16_stunnel_greyware_tool_keyword = "d686b1a4135947718e7a8157a8cb6694ed50e2267713de1972941148a8859789" nocase ascii wide

    condition:
        any of them
}