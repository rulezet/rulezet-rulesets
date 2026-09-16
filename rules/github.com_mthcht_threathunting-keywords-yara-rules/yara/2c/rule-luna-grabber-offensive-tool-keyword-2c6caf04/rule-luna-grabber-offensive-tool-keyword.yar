rule rule_Luna_Grabber_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Luna-Grabber' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Luna-Grabber"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Luna_Grabber_offensive_tool_keyword = /\sDisable_defender\.py/ nocase ascii wide
                        $string2_Luna_Grabber_offensive_tool_keyword = " Luna Grabber Builder" nocase ascii wide
                        $string3_Luna_Grabber_offensive_tool_keyword = /\ssigthief\.py/ nocase ascii wide
                        $string4_Luna_Grabber_offensive_tool_keyword = /\.\/Obfuscated_.{0,100}\.py/
                        $string5_Luna_Grabber_offensive_tool_keyword = /\/Disable_defender\.py/ nocase ascii wide
                        $string6_Luna_Grabber_offensive_tool_keyword = /\/Kill_protector\.py/ nocase ascii wide
                        $string7_Luna_Grabber_offensive_tool_keyword = /\/luna\.log/
                        $string8_Luna_Grabber_offensive_tool_keyword = /\/Luna\-Grabber\.git/ nocase ascii wide
                        $string9_Luna_Grabber_offensive_tool_keyword = "/Luna-Grabber/releases/download/" nocase ascii wide
                        $string10_Luna_Grabber_offensive_tool_keyword = "/Luna-Grabber/tarball/" nocase ascii wide
                        $string11_Luna_Grabber_offensive_tool_keyword = "/Luna-Grabber/zipball" nocase ascii wide
                        $string12_Luna_Grabber_offensive_tool_keyword = "/Luna-Grabber-Injection/main" nocase ascii wide
                        $string13_Luna_Grabber_offensive_tool_keyword = /\/sigthief\.py/ nocase ascii wide
                        $string14_Luna_Grabber_offensive_tool_keyword = /\/tools\/obfuscation\.py\s\-i\s/
                        $string15_Luna_Grabber_offensive_tool_keyword = /\\Disable_defender\.py/ nocase ascii wide
                        $string16_Luna_Grabber_offensive_tool_keyword = /\\Kill_protector\.py/ nocase ascii wide
                        $string17_Luna_Grabber_offensive_tool_keyword = /\\luna\.log/ nocase ascii wide
                        $string18_Luna_Grabber_offensive_tool_keyword = /\\Luna\-Logged\-.{0,100}\.zip/ nocase ascii wide
                        $string19_Luna_Grabber_offensive_tool_keyword = /\\roblox\scookies\.txt/ nocase ascii wide
                        $string20_Luna_Grabber_offensive_tool_keyword = /\\sigthief\.py/ nocase ascii wide
                        $string21_Luna_Grabber_offensive_tool_keyword = "1119pepesneakyevil" nocase ascii wide
                        $string22_Luna_Grabber_offensive_tool_keyword = "505bb78684c53f9fb96c92611bbd7ed7096c166f3621fc602b4f0402e0605621" nocase ascii wide
                        $string23_Luna_Grabber_offensive_tool_keyword = "5ac7b2c9c03ec6be6c8e0ea6ffd0b9ca0c69a8f2472d3e183780bfc6f86fc7f6" nocase ascii wide
                        $string24_Luna_Grabber_offensive_tool_keyword = "6f7204e9f37025c754fd990061bda4246aa63d13e4f9fe951c7a2871c2ecf5f5" nocase ascii wide
                        $string25_Luna_Grabber_offensive_tool_keyword = "9dc2d1ac93b43a6f3450e6d99201dfa4b7e75e8872d97b6cc90e455201ff0c83" nocase ascii wide
                        $string26_Luna_Grabber_offensive_tool_keyword = "BlankOBF v2: Obfuscates Python code to make it unreadable and hard to reverse" nocase ascii wide
                        $string27_Luna_Grabber_offensive_tool_keyword = "c2a640190d6567ec2b613cb2f3a37496a4df5450c577e4326b13457f69ba7160" nocase ascii wide
                        $string28_Luna_Grabber_offensive_tool_keyword = "caadd01f003376a0d92f5bcc416a1702802c5c1072907644e29f39fb2c6c513c" nocase ascii wide
                        $string29_Luna_Grabber_offensive_tool_keyword = "d71c3ea3ec686a8c080f8310b25cfe4696773a06fe151d03eb9a69de9147abcb" nocase ascii wide
                        $string30_Luna_Grabber_offensive_tool_keyword = "e2c3b2d10ba4db5f13e05de8197818f8ce94da878b5eba6c82a7feb73340b538" nocase ascii wide
                        $string31_Luna_Grabber_offensive_tool_keyword = "e6be8653e8355627406150a70434675aaad1cab5dbe2116237df5bf2ff7f4b45" nocase ascii wide
                        $string32_Luna_Grabber_offensive_tool_keyword = "f34b6048a755da93e66d8335d69d98eecc76dcb4ea0e7b816dc9af12ba8b6b22" nocase ascii wide
                        $string33_Luna_Grabber_offensive_tool_keyword = "f4d042d26b74e99f7442cbd0b9e3587f512fc6367f5759d6451d28856526db15" nocase ascii wide
                        $string34_Luna_Grabber_offensive_tool_keyword = /Luna\sGrabber\s\|\sCreated\sBy\sSmug/ nocase ascii wide
                        $string35_Luna_Grabber_offensive_tool_keyword = "Luna Grabber Builder - Running on v" nocase ascii wide
                        $string36_Luna_Grabber_offensive_tool_keyword = "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies" nocase ascii wide
                        $string37_Luna_Grabber_offensive_tool_keyword = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" nocase ascii wide
                        $string38_Luna_Grabber_offensive_tool_keyword = "SELECT origin_url, username_value, password_value FROM logins" nocase ascii wide
                        $string39_Luna_Grabber_offensive_tool_keyword = "Smug246/Luna-Grabber" nocase ascii wide
                        $string40_Luna_Grabber_offensive_tool_keyword = /Successfully\sobfuscated\sfile\:\s.{0,100}\.py/ nocase ascii wide
                        $string41_Luna_Grabber_offensive_tool_keyword = "You finally broke through BlankOBF v2; Give yourself a pat on your back!" nocase ascii wide
                        $string42_Luna_Grabber_offensive_tool_keyword = "Your version of Luna Token Grabber is outdated!" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}