rule rule_Goodsync_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Goodsync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Goodsync"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Goodsync_greyware_tool_keyword = /\/GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
                        $string2_Goodsync_greyware_tool_keyword = /\\CurrentControlSet\\Services\\GsServer/ nocase ascii wide
                        $string3_Goodsync_greyware_tool_keyword = /\\DIRECTORY\\BACKGROUND\\SHELL\\GOODSYNC/ nocase ascii wide
                        $string4_Goodsync_greyware_tool_keyword = /\\GoodSync\-2.{0,100}\-.{0,100}\.log/ nocase ascii wide
                        $string5_Goodsync_greyware_tool_keyword = /\\GOODSYNC2GO\.EXE/ nocase ascii wide
                        $string6_Goodsync_greyware_tool_keyword = /\\GOODSYNC2GO\-V.{0,100}\.EXE/ nocase ascii wide
                        $string7_Goodsync_greyware_tool_keyword = /\\GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
                        $string8_Goodsync_greyware_tool_keyword = /\\gs\-runner\.exe/ nocase ascii wide
                        $string9_Goodsync_greyware_tool_keyword = /\\GS\-SERVER\.EXE/ nocase ascii wide
                        $string10_Goodsync_greyware_tool_keyword = /\\Program\sFiles\\SIBER\sSYSTEMS\\GOODSYNC\\/ nocase ascii wide
                        $string11_Goodsync_greyware_tool_keyword = /\\Siber\sSystems\\GoodSync\\/ nocase ascii wide
                        $string12_Goodsync_greyware_tool_keyword = /\\Users\\.{0,100}\\AppData\\Local\\GoodSync/ nocase ascii wide
                        $string13_Goodsync_greyware_tool_keyword = ">GoodSync<" nocase ascii wide
                        $string14_Goodsync_greyware_tool_keyword = /\>gs\-runner\.exe\</ nocase ascii wide
                        $string15_Goodsync_greyware_tool_keyword = /Copy\sNew\s.{0,100}gdrive\:\/\/www\.googleapis\.com\/GS_Sync\// nocase ascii wide
                        $string16_Goodsync_greyware_tool_keyword = /Copy\sNew\s.{0,100}sftp\:\/\// nocase ascii wide
                        $string17_Goodsync_greyware_tool_keyword = "GoodSync Server" nocase ascii wide
                        $string18_Goodsync_greyware_tool_keyword = /GoodSync\-vsub\-2Go\-Setup\.exe/ nocase ascii wide
                        $string19_Goodsync_greyware_tool_keyword = /mediator\.goodsync\.com/ nocase ascii wide
                        $string20_Goodsync_greyware_tool_keyword = /Program\sFiles\\Siber\sSystems\\GoodSync/ nocase ascii wide
                        $string21_Goodsync_greyware_tool_keyword = /SOFTWARE\\Siber\sSystems\\GoodSync\\Profiles/ nocase ascii wide
                        $string22_Goodsync_greyware_tool_keyword = /temp.{0,100}\\gsync\.exe/ nocase ascii wide
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