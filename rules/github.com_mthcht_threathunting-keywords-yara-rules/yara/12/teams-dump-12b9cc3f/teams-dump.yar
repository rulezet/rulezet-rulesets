rule teams_dump
{
    meta:
        description = "Detection patterns for the tool 'teams_dump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teams_dump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\steams_dump\.py/ nocase ascii wide
                        $string2 = /\steams_dump\.py/ nocase ascii wide
                        $string3 = /\.py\steams\s\-\-get/ nocase ascii wide
                        $string4 = /\.py\steams\s\-\-list/ nocase ascii wide
                        $string5 = /\/teams_cookies_output\.json/ nocase ascii wide
                        $string6 = /\/teams_dump\.git/ nocase ascii wide
                        $string7 = /\/teams_dump\.git/ nocase ascii wide
                        $string8 = /\/teams_dump\.py/ nocase ascii wide
                        $string9 = /\/teams_dump\.py/ nocase ascii wide
                        $string10 = /\\teams_dump\.py/ nocase ascii wide
                        $string11 = /\\teams_dump\.py/ nocase ascii wide
                        $string12 = "0a0f2a82d5f3dbd8d9f8c6031b2ebb8c1820cf370e6b4fae2b1396cf2107dddd" nocase ascii wide
                        $string13 = "1f17ea5b2d547497145f092cc3b7f0ed8acbb821946a5d3265423b7262f2aa4f" nocase ascii wide
                        $string14 = "bc11b2b14526fef7b745fa22f0359235fab202060716f0c9544e4ef899c7312e" nocase ascii wide
                        $string15 = "byinarie/teams_dump" nocase ascii wide
                        $string16 = "byinarie/teams_dump" nocase ascii wide
                        $string17 = /teams_dump\.py\steams/ nocase ascii wide
                        $string18 = /teams_dump\-main\.zip/ nocase ascii wide
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