rule Snaffler
{
    meta:
        description = "Detection patterns for the tool 'Snaffler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Snaffler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\ssnaffler\.log/ nocase ascii wide
                        $string2 = /\/ShareFinder\.cs/ nocase ascii wide
                        $string3 = /\/SnaffCon\.cs/ nocase ascii wide
                        $string4 = "/SnaffCon/Snaffler" nocase ascii wide
                        $string5 = "/SnaffCore/" nocase ascii wide
                        $string6 = "/snafflertest/" nocase ascii wide
                        $string7 = /\/TreeWalker\.cs/ nocase ascii wide
                        $string8 = "SnaffCon/Snaffler" nocase ascii wide
                        $string9 = /SnaffCore\.csproj/ nocase ascii wide
                        $string10 = "SnaffCore/ActiveDirectory" nocase ascii wide
                        $string11 = "SnaffCore/Classifiers" nocase ascii wide
                        $string12 = "SnaffCore/Concurrency" nocase ascii wide
                        $string13 = "SnaffCore/Config" nocase ascii wide
                        $string14 = "SnaffCore/ShareFind" nocase ascii wide
                        $string15 = "SnaffCore/TreeWalk" nocase ascii wide
                        $string16 = /Snaffler\.csproj/ nocase ascii wide
                        $string17 = /snaffler\.exe/ nocase ascii wide
                        $string18 = /snaffler\.exe/ nocase ascii wide
                        $string19 = /snaffler\.log/ nocase ascii wide
                        $string20 = /Snaffler\.sln/ nocase ascii wide
                        $string21 = /Snaffler\.sln/ nocase ascii wide
                        $string22 = /SnafflerMessage\.cs/ nocase ascii wide
                        $string23 = /SnafflerMessageType\.cs/ nocase ascii wide
                        $string24 = /UltraSnaffCore\.csproj/ nocase ascii wide
                        $string25 = /UltraSnaffler\.sln/ nocase ascii wide
                        $string26 = /UltraSnaffler\.sln/ nocase ascii wide
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