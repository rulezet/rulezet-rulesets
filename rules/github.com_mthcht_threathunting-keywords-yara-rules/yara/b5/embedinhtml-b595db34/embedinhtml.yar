rule EmbedInHTML
{
    meta:
        description = "Detection patterns for the tool 'EmbedInHTML' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EmbedInHTML"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.bat\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string2 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.docm\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string3 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.docx\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string4 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.exe\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string5 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.js\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string6 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.pps\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string7 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.ppsx\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string8 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.ppt\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string9 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.ps1\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string10 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.xll\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string11 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.xls\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string12 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.xlsb\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string13 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.xlsm\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string14 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.xlsx\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string15 = /\.py\s\-k\s.{0,100}\s\-f\s.{0,100}\.doc\s\-o\s.{0,100}\.html/ nocase ascii wide
                        $string16 = /\/agent\/stagers\/dropbox\.py/ nocase ascii wide
                        $string17 = /\/EmbedInHTML\.git/ nocase ascii wide
                        $string18 = "/EmbedInHTML/" nocase ascii wide
                        $string19 = "36ff05fc406bf6a2e677374028ba00cb622b2219e44c198d5dd6efae4ae963c3" nocase ascii wide
                        $string20 = "809f540f580fc0e192a1c0432ec04105a3faf51f9d7c20f5e15423b78774052d" nocase ascii wide
                        $string21 = "Arno0x/EmbedInHTML" nocase ascii wide
                        $string22 = /embedInHTML\.html/ nocase ascii wide
                        $string23 = /embedInHTML\.py/ nocase ascii wide
                        $string24 = "EmbedInHTML-master" nocase ascii wide
                        $string25 = /\-f\spayloads_examples\/calc\./ nocase ascii wide
                        $string26 = /payloads_examples.{0,100}calc\.js/ nocase ascii wide
                        $string27 = /payloads_examples.{0,100}calc\.xll/ nocase ascii wide
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