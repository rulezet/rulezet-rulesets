rule rule_rsocks_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsocks"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_rsocks_greyware_tool_keyword = /\srsocks\.pool/ nocase ascii wide
                        $string2_rsocks_greyware_tool_keyword = /\srsocks\.server/ nocase ascii wide
                        $string3_rsocks_greyware_tool_keyword = /\.rsocks\.plist/ nocase ascii wide
                        $string4_rsocks_greyware_tool_keyword = "/bin/rsocks"
                        $string5_rsocks_greyware_tool_keyword = /\/com\.tonyseek\.rsocks\.plist/
                        $string6_rsocks_greyware_tool_keyword = "/opt/rsocks/"
                        $string7_rsocks_greyware_tool_keyword = /\/rsocks\.git/ nocase ascii wide
                        $string8_rsocks_greyware_tool_keyword = /\/rsocks\.git/
                        $string9_rsocks_greyware_tool_keyword = /\/rsocks\.toml/
                        $string10_rsocks_greyware_tool_keyword = "/rsocks/releases/download/" nocase ascii wide
                        $string11_rsocks_greyware_tool_keyword = "/rsocks_linux_amd64"
                        $string12_rsocks_greyware_tool_keyword = /\/rsocks_windows_386\.exe/ nocase ascii wide
                        $string13_rsocks_greyware_tool_keyword = /\\rsocks_windows_386\.exe/ nocase ascii wide
                        $string14_rsocks_greyware_tool_keyword = "14586f0477d31640096bf4749480b78c6a6c3afde3527bcc64e9d5f70d9e93ac" nocase ascii wide
                        $string15_rsocks_greyware_tool_keyword = "242194dbbdaca6aa7382e0b9f9677a2e7966bc6db8934119aa096e38a9fbf86d" nocase ascii wide
                        $string16_rsocks_greyware_tool_keyword = "4a97ad649c31411528694fdd8751bc6521f535f57022e6a6c0a39988df20d7b0" nocase ascii wide
                        $string17_rsocks_greyware_tool_keyword = "51a5737c2b51190507d47557023264299f8de0b2152e89e093e0e61f64807986" nocase ascii wide
                        $string18_rsocks_greyware_tool_keyword = "a539e169941f55d687ca44c90a5a90715dd23871a04a64f1712e08e758df0ec0" nocase ascii wide
                        $string19_rsocks_greyware_tool_keyword = "a9a87bdcf06a8b5ee41a1eec95c0f9c813a5f29ba6d8eec28b07d8331aa5eb85" nocase ascii wide
                        $string20_rsocks_greyware_tool_keyword = "brimstone/rsocks" nocase ascii wide
                        $string21_rsocks_greyware_tool_keyword = "easy_install rsocks" nocase ascii wide
                        $string22_rsocks_greyware_tool_keyword = "import socket, socks, listen, serve, wrap_ssl, GreenPool" nocase ascii wide
                        $string23_rsocks_greyware_tool_keyword = "pip install rsocks" nocase ascii wide
                        $string24_rsocks_greyware_tool_keyword = "pip install -U rsocks" nocase ascii wide
                        $string25_rsocks_greyware_tool_keyword = "rsocks --config" nocase ascii wide
                        $string26_rsocks_greyware_tool_keyword = /rsocks\/server\.py/ nocase ascii wide
                        $string27_rsocks_greyware_tool_keyword = /rsocks\\server\.py/ nocase ascii wide
                        $string28_rsocks_greyware_tool_keyword = "tonyseek/rsocks" nocase ascii wide

    condition:
        any of them
}