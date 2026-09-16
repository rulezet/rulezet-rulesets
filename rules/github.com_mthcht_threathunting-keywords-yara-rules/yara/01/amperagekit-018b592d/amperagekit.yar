rule AmperageKit
{
    meta:
        description = "Detection patterns for the tool 'AmperageKit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AmperageKit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/Amperage\.exe/ nocase ascii wide
                        $string2 = /\/AmperageKit\.git/ nocase ascii wide
                        $string3 = "/AmperageKit/releases/" nocase ascii wide
                        $string4 = /\\Amperage\.exe/ nocase ascii wide
                        $string5 = /\\Amperage\\Program\.cs/ nocase ascii wide
                        $string6 = /\\Amperage_v2024\.5\.31_arm64\.zip/ nocase ascii wide
                        $string7 = /\\Amperage_v2024\.6\.1_arm64\.zip/ nocase ascii wide
                        $string8 = /\\AmperageAIXSysRemove/ nocase ascii wide
                        $string9 = /\\AmperageHwReqDetour/ nocase ascii wide
                        $string10 = /\\AmperageKit\.sln/ nocase ascii wide
                        $string11 = /\\ProgramData\\Amperage/ nocase ascii wide
                        $string12 = "327F3F26-182F-4E58-ABEA-A0CEDBCA0FCD" nocase ascii wide
                        $string13 = "3bdf7c5f0c87c94b461668137a3e7cbf757d59dafc7a063362c34d17f2f33e61" nocase ascii wide
                        $string14 = "7334543f2f3555690c9a4995cf1d8e83beb9fa45e6aa147c49114a4ef89670b8" nocase ascii wide
                        $string15 = "75dce532b65a7c7644a626196a8af9d8370e163e802847505fb033a6290fb4a5" nocase ascii wide
                        $string16 = "7931404e96b6aff52bc81a852f1f545f0cd07712d648099ec0618f4e66a1807f" nocase ascii wide
                        $string17 = "80C7245C-B926-4CEB-BA5B-5353736137A8" nocase ascii wide
                        $string18 = "8e454334de0de74a6e53ee1d26e24cd2b0f41427922d9e92e6d49cf5db942a3c" nocase ascii wide
                        $string19 = "A3454AF1-12AF-4952-B26D-FF0930DB779E" nocase ascii wide
                        $string20 = "Amperage - Recall setup tool for unsupported hardware" nocase ascii wide
                        $string21 = "cd1c54a8510c1e09d55868e12872aa54f9dc9ade95d70f08a173d29f6d676fde" nocase ascii wide
                        $string22 = "d84efd06178700a83d135862d6c7419dce2e12df92c78850dc7cc5b1da482abd" nocase ascii wide
                        $string23 = "ed0375afd9b26b18fd9b72bbb416dbf8bec289bf135facf4b7ba5cd2b1d86208" nocase ascii wide
                        $string24 = "Removing AIX package from all standard users" nocase ascii wide
                        $string25 = "thebookisclosed/AmperageKit" nocase ascii wide
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