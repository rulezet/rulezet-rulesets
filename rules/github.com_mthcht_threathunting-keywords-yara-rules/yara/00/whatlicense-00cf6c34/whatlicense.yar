rule whatlicense
{
    meta:
        description = "Detection patterns for the tool 'whatlicense' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whatlicense"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\-t\swl\-extract\.dll\s\-d\s.{0,100}\.dat\s\-r\s.{0,100}\.rsa\s\-.{0,100}\.exe/ nocase ascii wide
                        $string2 = /\/whatlicense\.git/ nocase ascii wide
                        $string3 = /\\whatlicense\-main\\/ nocase ascii wide
                        $string4 = /\\wl_log\.txt/ nocase ascii wide
                        $string5 = /\\wl\-lic\.exe/ nocase ascii wide
                        $string6 = /\\wl\-lic\.pdb/ nocase ascii wide
                        $string7 = "639EF517-FCFC-408E-9500-71F0DC0458DB" nocase ascii wide
                        $string8 = "CC127443-2519-4E04-8865-A6887658CDE5" nocase ascii wide
                        $string9 = "charlesnathansmith/whatlicense" nocase ascii wide
                        $string10 = /whatlicense\-main\.zip/ nocase ascii wide
                        $string11 = /wl\-lic\s\-d\s.{0,100}\.dat\s\-r\s.{0,100}\.rsa/ nocase ascii wide
                        $string12 = /wl\-lic\s\-h\sHWID\s\-m\smain_hash\s\-d\sregkey2\.dat\s\-r\sregkey2\.rsa/ nocase ascii wide
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