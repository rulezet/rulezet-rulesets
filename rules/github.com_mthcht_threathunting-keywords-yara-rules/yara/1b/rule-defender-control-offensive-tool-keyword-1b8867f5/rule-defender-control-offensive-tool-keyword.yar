rule rule_defender_control_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'defender-control' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "defender-control"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_defender_control_offensive_tool_keyword = /\/dControl\.exe/ nocase ascii wide
                        $string2_defender_control_offensive_tool_keyword = /\/dControl\.rar/ nocase ascii wide
                        $string3_defender_control_offensive_tool_keyword = /\/Defender\sControl\.zip/ nocase ascii wide
                        $string4_defender_control_offensive_tool_keyword = /\/defender\-control\.git/ nocase ascii wide
                        $string5_defender_control_offensive_tool_keyword = /\/defendercontrol\.zip/ nocase ascii wide
                        $string6_defender_control_offensive_tool_keyword = /\/defenderOff\.rar/ nocase ascii wide
                        $string7_defender_control_offensive_tool_keyword = /\/disable\-defender\.exe/ nocase ascii wide
                        $string8_defender_control_offensive_tool_keyword = /\/enable\-defender\.exe/ nocase ascii wide
                        $string9_defender_control_offensive_tool_keyword = /\\dControl\.exe/ nocase ascii wide
                        $string10_defender_control_offensive_tool_keyword = /\\dControl\.rar/ nocase ascii wide
                        $string11_defender_control_offensive_tool_keyword = /\\Defender\sControl\.zip/ nocase ascii wide
                        $string12_defender_control_offensive_tool_keyword = /\\defender\-control\.sln/ nocase ascii wide
                        $string13_defender_control_offensive_tool_keyword = /\\defendercontrol\.zip/ nocase ascii wide
                        $string14_defender_control_offensive_tool_keyword = /\\defender\-control\\dcontrol\.cpp/ nocase ascii wide
                        $string15_defender_control_offensive_tool_keyword = /\\defenderOff\.rar/ nocase ascii wide
                        $string16_defender_control_offensive_tool_keyword = /\\disable\-defender\.exe/ nocase ascii wide
                        $string17_defender_control_offensive_tool_keyword = /\\dt87xz\\Defender_Settings\.vbs/ nocase ascii wide
                        $string18_defender_control_offensive_tool_keyword = /\\enable\-defender\.exe/ nocase ascii wide
                        $string19_defender_control_offensive_tool_keyword = /\\Root\\InventoryApplicationFile\\defender\-control/ nocase ascii wide
                        $string20_defender_control_offensive_tool_keyword = /\>dControl\sv2\.1\</ nocase ascii wide
                        $string21_defender_control_offensive_tool_keyword = ">defender-control<" nocase ascii wide
                        $string22_defender_control_offensive_tool_keyword = "000417262bbfa790d2c3a9f66236dc996b8079c4eb05240301d5de17e5cf6749" nocase ascii wide
                        $string23_defender_control_offensive_tool_keyword = "089CA7D6-3277-4998-86AF-F6413290A442" nocase ascii wide
                        $string24_defender_control_offensive_tool_keyword = "1ef6c1a4dfdc39b63bfe650ca81ab89510de6c0d3d7c608ac5be80033e559326" nocase ascii wide
                        $string25_defender_control_offensive_tool_keyword = "1ef6c1a4dfdc39b63bfe650ca81ab89510de6c0d3d7c608ac5be80033e559326" nocase ascii wide
                        $string26_defender_control_offensive_tool_keyword = /2015\-2022\swww\.sordum\.org\sAll\sRights\sReserved/ nocase ascii wide
                        $string27_defender_control_offensive_tool_keyword = "2df52ae297704f333af2c7e29544d0c00fcbbccaeb343a8588f9792d482b75a0" nocase ascii wide
                        $string28_defender_control_offensive_tool_keyword = "435c30dbc7c59f5d013f8088b1f9be04ba003a4d04d7f69d8006bdf190a84bee" nocase ascii wide
                        $string29_defender_control_offensive_tool_keyword = "45bf0057b3121c6e444b316afafdd802d16083282d1cbfde3cdbf2a9d0915ace" nocase ascii wide
                        $string30_defender_control_offensive_tool_keyword = "49f487316920c28f546082c345a58fad4bd470507ddc74f34a2515110f193b7d" nocase ascii wide
                        $string31_defender_control_offensive_tool_keyword = "53bf7ddf48f5231ddaec4e8fe47636f62541226c5bb53374012a68f75c182451" nocase ascii wide
                        $string32_defender_control_offensive_tool_keyword = "53bf7ddf48f5231ddaec4e8fe47636f62541226c5bb53374012a68f75c182451" nocase ascii wide
                        $string33_defender_control_offensive_tool_keyword = "57fc37bfab5489b2ace66257d03b23a098ddc80d25b22540e0e5745becc4dbad" nocase ascii wide
                        $string34_defender_control_offensive_tool_keyword = "688332c4667e6d6e605356fbf205017a7dc9a86731d9fd95beb2562df3bc754b" nocase ascii wide
                        $string35_defender_control_offensive_tool_keyword = "782ceb859eaa767d4e24ae709d7ab3c0dea3b450c788e04fb2ce4c085e9e8a91" nocase ascii wide
                        $string36_defender_control_offensive_tool_keyword = "7c2c0aec-7b9d-4104-99fa-1844d609452c" nocase ascii wide
                        $string37_defender_control_offensive_tool_keyword = "7e94404dc46259916898e5400c4511f885e873dd0fe75357c178053b60b6f7ed" nocase ascii wide
                        $string38_defender_control_offensive_tool_keyword = "8ba095144dbfff485b4f4db04c338ef687a58306043dad87fe447f219120d1a0" nocase ascii wide
                        $string39_defender_control_offensive_tool_keyword = "8e25d415c6b4cf0960429c6c9e1ab7720d4dcd637ee15e0e13bcc82d7d7b203b" nocase ascii wide
                        $string40_defender_control_offensive_tool_keyword = "8e456a357b00fa82bc589a1a13f4dac4ace146083709d6e53106f86095df0f8d" nocase ascii wide
                        $string41_defender_control_offensive_tool_keyword = "8e9a84da243905685ca77b6ef71841e610b88b7963d4de59f6dcbdd1621ecacd" nocase ascii wide
                        $string42_defender_control_offensive_tool_keyword = "8e9a84da243905685ca77b6ef71841e610b88b7963d4de59f6dcbdd1621ecacd" nocase ascii wide
                        $string43_defender_control_offensive_tool_keyword = "909cb2ae71b22db86c4232041f32352ff94db59760593ada386bde5b4dc8901a" nocase ascii wide
                        $string44_defender_control_offensive_tool_keyword = "92105bc571692ebbab9f00a66c370901439375f98cfca4986f576d9c808dff38" nocase ascii wide
                        $string45_defender_control_offensive_tool_keyword = "92105bc571692ebbab9f00a66c370901439375f98cfca4986f576d9c808dff38" nocase ascii wide
                        $string46_defender_control_offensive_tool_keyword = "94c7153749f9d9e3d12da8ff2201927599003808cee82316e9bc632387aeb0cc" nocase ascii wide
                        $string47_defender_control_offensive_tool_keyword = "962d2a4f2088fbe103c6b38d151689ba100458978ca37a2a9b62047a029f8d33" nocase ascii wide
                        $string48_defender_control_offensive_tool_keyword = "9d847494b219b153345479919af7ca0e11e253c9f782fafeee8f74c63862c8a2" nocase ascii wide
                        $string49_defender_control_offensive_tool_keyword = "a0c0ea6786bf9ed2a243e6363409ba76b4f821e64d79e2587501050a46f3e326" nocase ascii wide
                        $string50_defender_control_offensive_tool_keyword = "af42a17d428c8e9d6f4a6d3393ec268f4d12bbfd01a897d87275482a45c847e9" nocase ascii wide
                        $string51_defender_control_offensive_tool_keyword = "b6a20cc4035c440aa539a0a8828d4372c9b160002ef9f0e44d9f9e89ed1dfcd0" nocase ascii wide
                        $string52_defender_control_offensive_tool_keyword = "b8860da17ef3184d74987dd804109669ab503b2faa70438b8072f27b24f6c00a" nocase ascii wide
                        $string53_defender_control_offensive_tool_keyword = "c1ae1df5425338331c97fc3c3892b01aeaa7d0562369d66d6178a33e6d1f00a0" nocase ascii wide
                        $string54_defender_control_offensive_tool_keyword = "cd6857024c9a8bbb90a71a2bdaa72e13a0c7be30d288fe81eda8bb98785e5834" nocase ascii wide
                        $string55_defender_control_offensive_tool_keyword = "d65432a573f67dd33aada2c4dd6ff20d76a7235b2f525979aac588702c4e2364" nocase ascii wide
                        $string56_defender_control_offensive_tool_keyword = "d87a4da0ba80cee6c60be1a1ebc2c138a79682ca7ad2ef8b91c2035e9a7ecd40" nocase ascii wide
                        $string57_defender_control_offensive_tool_keyword = "db6749f21079d875bf04af8c1eef3e2e8e2972818273c3032bd8c843f2d72cda" nocase ascii wide
                        $string58_defender_control_offensive_tool_keyword = /Defender\sControl\sv2\.1\s\-\sAuthor\sby\sBlueLife/ nocase ascii wide
                        $string59_defender_control_offensive_tool_keyword = "e5eb2c94e78da85d2a4b0cf973bab87ab3e9d877da6a169d3f2cf9b40eb73a1b" nocase ascii wide
                        $string60_defender_control_offensive_tool_keyword = "feb09cc39b1520d228e9e9274500b8c229016d6fc8018a2bf19aa9d3601492c5" nocase ascii wide
                        $string61_defender_control_offensive_tool_keyword = /https\:\/\/drive\.usercontent\.google\.com\/download\?id\=1Up7tr9Zh2e7FVLOdx5J1We3GJLGxEAMO\&export\=download/ nocase ascii wide
                        $string62_defender_control_offensive_tool_keyword = /https\:\/\/www\.sordum\.org\/downloads\/\?st\-defender\-control/ nocase ascii wide
                        $string63_defender_control_offensive_tool_keyword = "net stop badrv" nocase ascii wide
                        $string64_defender_control_offensive_tool_keyword = "net1 stop badrv" nocase ascii wide
                        $string65_defender_control_offensive_tool_keyword = "pgkt04/defender-control" nocase ascii wide
                        $string66_defender_control_offensive_tool_keyword = /tCommand\s\=\s\\"windowsdefender\:\/\/Threatsettings\\".{0,100}CreateObject\(\\"Shell\.Application\\"\)\.ShellExecute\(tCommand\)/ nocase ascii wide
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