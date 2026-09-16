rule rule_REC2__offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'REC2 ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "REC2 "
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_REC2__offensive_tool_keyword = /\/REC2\.git/ nocase ascii wide
                        $string2_REC2__offensive_tool_keyword = /\\REC2\-main\.zip/ nocase ascii wide
                        $string3_REC2__offensive_tool_keyword = "a78983b009b688a82458abac952516db57dc7eb3118a35cc737dde29c7b87ec4" nocase ascii wide
                        $string4_REC2__offensive_tool_keyword = "c2server_arm_musl" nocase ascii wide
                        $string5_REC2__offensive_tool_keyword = "c2server_armv7" nocase ascii wide
                        $string6_REC2__offensive_tool_keyword = "c2server_debug" nocase ascii wide
                        $string7_REC2__offensive_tool_keyword = "c2server_linux"
                        $string8_REC2__offensive_tool_keyword = "c2server_macos" nocase ascii wide
                        $string9_REC2__offensive_tool_keyword = "c2server_release" nocase ascii wide
                        $string10_REC2__offensive_tool_keyword = "c2server_windows" nocase ascii wide
                        $string11_REC2__offensive_tool_keyword = /crate\:\:modules\:\:\{rec2mastodon.{0,100}rec2virustotal\}/ nocase ascii wide
                        $string12_REC2__offensive_tool_keyword = "d09ccee4-pass-word-0000-98677e2356fd" nocase ascii wide
                        $string13_REC2__offensive_tool_keyword = "g0h4n/REC2" nocase ascii wide
                        $string14_REC2__offensive_tool_keyword = /https\:\/\/mastodon\.be\/\@username_fzihfzuhfuoz\/109994357971853428/ nocase ascii wide
                        $string15_REC2__offensive_tool_keyword = /https\:\/\/mastodon\.be\/username_fzihfzuhfuoz\/109743339821428173/ nocase ascii wide
                        $string16_REC2__offensive_tool_keyword = "RAMDOMdd28f0dcd9779315ee130deb565dbf315587f1611e54PASSWORD" nocase ascii wide
                        $string17_REC2__offensive_tool_keyword = "REC2 implant for Mastodon" nocase ascii wide
                        $string18_REC2__offensive_tool_keyword = "REC2 implant for VirusTotal" nocase ascii wide
                        $string19_REC2__offensive_tool_keyword = "rec2::modules::rec2mastodon" nocase ascii wide
                        $string20_REC2__offensive_tool_keyword = /rec2_mastodon_x64\.exe/ nocase ascii wide
                        $string21_REC2__offensive_tool_keyword = /rec2_virustotal_x64\.exe/ nocase ascii wide
                        $string22_REC2__offensive_tool_keyword = /rec2mastodon\.rs/ nocase ascii wide
                        $string23_REC2__offensive_tool_keyword = "rec2virustotal" nocase ascii wide
                        $string24_REC2__offensive_tool_keyword = /rec2virustotal\.rs/ nocase ascii wide
                        $string25_REC2__offensive_tool_keyword = "TMVB6XJWzuz4KsqUCnwxrtooQV9LmP6R4IX62HeQ7OZzhxgsahsxNzf05dJNkntl" nocase ascii wide
                        $string26_REC2__offensive_tool_keyword = "Using VirusToal website as external C2" nocase ascii wide
                        $string27_REC2__offensive_tool_keyword = "WkIKjtCbQzcqQd04ZsE4sFefvpjryhU5w9iVFxGz1oU" nocase ascii wide
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