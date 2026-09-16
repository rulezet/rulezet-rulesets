rule rule_BrowserSnatch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BrowserSnatch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BrowserSnatch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BrowserSnatch_offensive_tool_keyword = /\/BrowserSnatch\.git/ nocase ascii wide
                        $string2_BrowserSnatch_offensive_tool_keyword = "/BrowserSnatch/releases/download" nocase ascii wide
                        $string3_BrowserSnatch_offensive_tool_keyword = "/BrowserSnatch-master" nocase ascii wide
                        $string4_BrowserSnatch_offensive_tool_keyword = /\\BrowserSnatch\.sln/ nocase ascii wide
                        $string5_BrowserSnatch_offensive_tool_keyword = /\\BrowserSnatch\-master/ nocase ascii wide
                        $string6_BrowserSnatch_offensive_tool_keyword = /\\ChromiumDecryptor\.cpp/ nocase ascii wide
                        $string7_BrowserSnatch_offensive_tool_keyword = "08cebde6781422f271581951ff6db23b9eedd4a0be0949551c0da85c6de8cb72" nocase ascii wide
                        $string8_BrowserSnatch_offensive_tool_keyword = "0f898913633b4dad45a631e63466f6b76e591f896118bab6e718ab3c8587911f" nocase ascii wide
                        $string9_BrowserSnatch_offensive_tool_keyword = "3246bb6e6b258b85286ae566dbde16e6e61c35d21be06a0d03b1aad376efb411" nocase ascii wide
                        $string10_BrowserSnatch_offensive_tool_keyword = "3f8db721f5791fcaaef7d22b50a1cd6a87be8f07262c145ad66a18f832d75839" nocase ascii wide
                        $string11_BrowserSnatch_offensive_tool_keyword = "493e415ef774fe3a7c3ba17a524f02d72bd36b1a49d8e9e0734eecf1d5834155" nocase ascii wide
                        $string12_BrowserSnatch_offensive_tool_keyword = "569d0ac16a89509e1de01deab2fefe2731a48bec2ab7794d9ac0628a6baf2481" nocase ascii wide
                        $string13_BrowserSnatch_offensive_tool_keyword = "7dbc46ea673ab508a7b9121b0a49d29470a8fc01669105173fd2a52f88dd946a" nocase ascii wide
                        $string14_BrowserSnatch_offensive_tool_keyword = "7de6e20c24d452409937f4869770848445952afa1ff26288dfb558d8edc64def" nocase ascii wide
                        $string15_BrowserSnatch_offensive_tool_keyword = "87440f0b-dacf-4695-a483-031fdc0b0194" nocase ascii wide
                        $string16_BrowserSnatch_offensive_tool_keyword = "a3fbc9a01ac82d10f92da72625f1a092817c5fad7a9b60917b811fab1ff8c97f" nocase ascii wide
                        $string17_BrowserSnatch_offensive_tool_keyword = "BrowserSnatch -" nocase ascii wide
                        $string18_BrowserSnatch_offensive_tool_keyword = "BrowserSnatch executed with " nocase ascii wide
                        $string19_BrowserSnatch_offensive_tool_keyword = /BrowserSnatch\sv1\.0\s\-\sA\sversatile\sbrowser\sdata\sextraction\stool/ nocase ascii wide
                        $string20_BrowserSnatch_offensive_tool_keyword = /BrowserSnatch\.exe/ nocase ascii wide
                        $string21_BrowserSnatch_offensive_tool_keyword = /BrowserSnatch64\.exe/ nocase ascii wide
                        $string22_BrowserSnatch_offensive_tool_keyword = /BrowserSnatch\-master\.zip/ nocase ascii wide
                        $string23_BrowserSnatch_offensive_tool_keyword = "Chromium Bookmarks Snatch Failed" nocase ascii wide
                        $string24_BrowserSnatch_offensive_tool_keyword = "Chromium Cookie Snatch Failed" nocase ascii wide
                        $string25_BrowserSnatch_offensive_tool_keyword = "Chromium History Snatch Failed" nocase ascii wide
                        $string26_BrowserSnatch_offensive_tool_keyword = "Chromium Password Snatch Failed" nocase ascii wide
                        $string27_BrowserSnatch_offensive_tool_keyword = "dc12cf2c161aea6ad015a11593b74603e25a4c7754b96b3d3b4062bd0e5d5a09" nocase ascii wide
                        $string28_BrowserSnatch_offensive_tool_keyword = /dns\.msfncsi\.com/ nocase ascii wide
                        $string29_BrowserSnatch_offensive_tool_keyword = "e7711f13b26f4b8f260587592d92f5d04e4aec5124896a35f082b69785e51d26" nocase ascii wide
                        $string30_BrowserSnatch_offensive_tool_keyword = "f58cbacfd41c4b0d5411a48f8142489dbde75c79211f37cb3c11a5063ebb6c2f" nocase ascii wide
                        $string31_BrowserSnatch_offensive_tool_keyword = "Gecko Bookmarks Snatch Failed" nocase ascii wide
                        $string32_BrowserSnatch_offensive_tool_keyword = "Gecko Cookie Snatch Failed" nocase ascii wide
                        $string33_BrowserSnatch_offensive_tool_keyword = "Gecko History Snatch Failed" nocase ascii wide
                        $string34_BrowserSnatch_offensive_tool_keyword = "Gecko Password Snatch Failed" nocase ascii wide
                        $string35_BrowserSnatch_offensive_tool_keyword = /https\:\/\/0x00sec\.org\/t\/malware\-development\-1\-password\-stealers\-chrome\/33571/ nocase ascii wide
                        $string36_BrowserSnatch_offensive_tool_keyword = "shaddy43/BrowserSnatch" nocase ascii wide
                        $string37_BrowserSnatch_offensive_tool_keyword = "Snatching passwords & cookies" nocase ascii wide
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