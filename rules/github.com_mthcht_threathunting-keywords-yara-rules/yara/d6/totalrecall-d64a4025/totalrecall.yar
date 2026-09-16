rule TotalRecall
{
    meta:
        description = "Detection patterns for the tool 'TotalRecall' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TotalRecall"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Recall folder found: " nocase ascii wide
                        $string2 = /\s\-\-search\spassword\s\-\-from_date\s.{0,100}\s\-\-to_date\s/ nocase ascii wide
                        $string3 = /\stotalrecall\.py/ nocase ascii wide
                        $string4 = /\sWindows\sRecall\sfeature\sfound\.\sDo\syou\swant\sto\sproceed\swith\sthe\sextraction\?/ nocase ascii wide
                        $string5 = /\sWindows\sRecall\sfeature\snot\sfound\.\sNothing\sto\sextract/ nocase ascii wide
                        $string6 = /\/TotalRecall\.git/ nocase ascii wide
                        $string7 = /\/totalrecall\.py/ nocase ascii wide
                        $string8 = /\/TotalRecall\.txt/
                        $string9 = /\\2024\-.{0,100}_Recall_Extraction\\/ nocase ascii wide
                        $string10 = /\\2025\-.{0,100}_Recall_Extraction\\/ nocase ascii wide
                        $string11 = /\\totalrecall\.py/ nocase ascii wide
                        $string12 = /\\TotalRecall\.txt/ nocase ascii wide
                        $string13 = /\\TotalRecall\\.{0,100}_Recall_Extraction/ nocase ascii wide
                        $string14 = "353f18e314f024ceea013bd97c140e09fd4ac715bf9ac7c965d0b89845dffcf0" nocase ascii wide
                        $string15 = /C\:\\\\Users\\\\\{username\}\\\\AppData\\\\Local\\\\CoreAIPlatform\.00\\\\UKP/ nocase ascii wide
                        $string16 = /extraction_folder.{0,100}TotalRecall\.txt/ nocase ascii wide
                        $string17 = /SELECT\sWindowTitle\,\sTimeStamp\,\sImageToken\s.{0,100}FROM\sWindowCapture/ nocase ascii wide
                        $string18 = "xaitax/TotalRecall" nocase ascii wide
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