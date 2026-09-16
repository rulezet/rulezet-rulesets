rule rule_eraser_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'eraser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "eraser"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_eraser_greyware_tool_keyword = /\serase\s\/quiet\s\/method\=.{0,100}\sdata\sdir\=/ nocase ascii wide
                        $string2_eraser_greyware_tool_keyword = /\serase\s\/quiet\s\/methodName\=.{0,100}\sdata\sdir\=/ nocase ascii wide
                        $string3_eraser_greyware_tool_keyword = /\/Eraser\s5\.8\.8\.exe/ nocase ascii wide
                        $string4_eraser_greyware_tool_keyword = /\/Eraser\s6\.0\.10\.2620\.exe/ nocase ascii wide
                        $string5_eraser_greyware_tool_keyword = /\/Eraser\s6\.0\.8\.2273\.exe/ nocase ascii wide
                        $string6_eraser_greyware_tool_keyword = /\/Eraser\s6\.0\.9\.2343\.exe/ nocase ascii wide
                        $string7_eraser_greyware_tool_keyword = /\/Eraser\s6\.2\.0\.2994\.exe/ nocase ascii wide
                        $string8_eraser_greyware_tool_keyword = /\/EraserSetup\.exe/ nocase ascii wide
                        $string9_eraser_greyware_tool_keyword = /\\AppData\\Local\\Temp\\eraserInstallBootstrapper\\/ nocase ascii wide
                        $string10_eraser_greyware_tool_keyword = /\\Eraser\s\(x64\)\.msi/ nocase ascii wide
                        $string11_eraser_greyware_tool_keyword = /\\Eraser\s\(x86\)\.msi/ nocase ascii wide
                        $string12_eraser_greyware_tool_keyword = /\\Eraser\s5\.8\.8\.exe/ nocase ascii wide
                        $string13_eraser_greyware_tool_keyword = /\\Eraser\s6\.0\.10\.2620\.exe/ nocase ascii wide
                        $string14_eraser_greyware_tool_keyword = /\\Eraser\s6\.0\.8\.2273\.exe/ nocase ascii wide
                        $string15_eraser_greyware_tool_keyword = /\\Eraser\s6\.0\.9\.2343\.exe/ nocase ascii wide
                        $string16_eraser_greyware_tool_keyword = /\\Eraser\s6\.2\.0\.2994\.exe/ nocase ascii wide
                        $string17_eraser_greyware_tool_keyword = /\\EraserSetup\.exe/ nocase ascii wide
                        $string18_eraser_greyware_tool_keyword = /\\Microsoft\\Windows\\CurrentVersion\\Run\\Eraser/ nocase ascii wide
                        $string19_eraser_greyware_tool_keyword = /\\Microsoft\\Windows\\Start\sMenu\\Programs\\Eraser\\Eraser\.lnk/ nocase ascii wide
                        $string20_eraser_greyware_tool_keyword = /\\Program\sFiles\\Eraser\\/ nocase ascii wide
                        $string21_eraser_greyware_tool_keyword = /\\Public\\Desktop\\Eraser\.lnk/ nocase ascii wide
                        $string22_eraser_greyware_tool_keyword = /\\Windows\\Start\sMenu\\Programs\\Eraser\\Eraser\sVerify\.lnk/ nocase ascii wide
                        $string23_eraser_greyware_tool_keyword = /\\Windows\\Start\sMenu\\Programs\\Eraser\\Eraser\sWebsite\.url/ nocase ascii wide
                        $string24_eraser_greyware_tool_keyword = ">Eraser - Secure Information Removal Tool<" nocase ascii wide
                        $string25_eraser_greyware_tool_keyword = ">Eraser Setup Bootstrapper<" nocase ascii wide
                        $string26_eraser_greyware_tool_keyword = "47e484261a88ba1a895699d8ff0239e1f5089b4a96128e8e610e2b41a9bd4605" nocase ascii wide
                        $string27_eraser_greyware_tool_keyword = "491301f6b3bc5074f978eb8ad5629923be5e5a750f43d7df96fc9c48612a0016" nocase ascii wide
                        $string28_eraser_greyware_tool_keyword = "4ce2ba1b4eabaf58b763ac456397b43ece17e9803e806bf405b28c386a484f6a" nocase ascii wide
                        $string29_eraser_greyware_tool_keyword = "9d3a9deeeac5f53514e20f1a6dacd125ddec7e17e18d27c23a276ed5eb608878" nocase ascii wide
                        $string30_eraser_greyware_tool_keyword = "a03578a6b28aff267f20a87755696a91a1d5b923e815b2989e4afcc8915cc357" nocase ascii wide
                        $string31_eraser_greyware_tool_keyword = "a09787812790b59ec3d36120788ae9f80b7bdda1e2d7a17a46d8112324632737" nocase ascii wide
                        $string32_eraser_greyware_tool_keyword = "bbc22b7149e74ee2ca344ebc55207e6bae4837b77857c7e9ef9e16682d7c8c49" nocase ascii wide
                        $string33_eraser_greyware_tool_keyword = "ee4026fe96e047558bedd20cf870d1f8348beb91a2c88fbf4cedd6357e316f1d" nocase ascii wide
                        $string34_eraser_greyware_tool_keyword = /Eraser\.exe\saddtask\s/ nocase ascii wide
                        $string35_eraser_greyware_tool_keyword = /PortableApps\.com\/EraserPortable/ nocase ascii wide
                        $string36_eraser_greyware_tool_keyword = /sourceforge\.net\/projects\/eraser\/files\/Eraser.{0,100}\/download/ nocase ascii wide
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