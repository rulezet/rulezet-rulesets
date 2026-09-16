rule anyviewer
{
    meta:
        description = "Detection patterns for the tool 'anyviewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anyviewer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/AnyViewerSetup\.exe/ nocase ascii wide
                        $string2 = /\\AnyViewerSetup\.exe/ nocase ascii wide
                        $string3 = /\\AnyViewerSetup\.tmp/ nocase ascii wide
                        $string4 = /\\logs\\RCService\.txt/ nocase ascii wide
                        $string5 = ">AnyViewer Setup<" nocase ascii wide
                        $string6 = ">AnyViewer<" nocase ascii wide
                        $string7 = "0de968ffd4a6c60413cac739dccb1b162f8f93f3db754728fde8738e52706fa4" nocase ascii wide
                        $string8 = "334ec9e7d937c42e8ef12f9d4ec90862ecc5410c06442393a38390b34886aa59" nocase ascii wide
                        $string9 = /a\.aomeisoftware\.com/ nocase ascii wide
                        $string10 = /AnyViewer\\audio_sniffer\.dll/ nocase ascii wide
                        $string11 = /AnyViewer\\AVCore\.exe/ nocase ascii wide
                        $string12 = /AnyViewer\\RCService\.exe/ nocase ascii wide
                        $string13 = /AnyViewer\\ScreanCap\.exe/ nocase ascii wide
                        $string14 = /AnyViewer\\SplashWin\.exe/ nocase ascii wide
                        $string15 = /controlserver\.anyviewer\.com/ nocase ascii wide
                        $string16 = /https\:\/\/ip138\.com\/iplookup\.asp\?ip\=.{0,100}\&action\=2/ nocase ascii wide
                        $string17 = /Program\sFiles\s\(x86\)\\AnyViewer/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}