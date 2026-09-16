rule rule_OffensiveNotion_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OffensiveNotion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveNotion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OffensiveNotion_offensive_tool_keyword = /\s\/create\s\/tn\sNotion\s\/tr\s\\.{0,100}cmd\.exe.{0,100}\s\-c\s.{0,100}\\.{0,100}\s\/sc\sonlogon\s\/ru\sSystem\\/ nocase ascii wide
                        $string2_OffensiveNotion_offensive_tool_keyword = /\$FilterArgs\s\=\s\@\{\sname\=\'Notion\'.{0,100}EventNameSpace\=\'root\\\\CimV2\'.{0,100}QueryLanguage\=.{0,100}WQL.{0,100}\sQuery\=.{0,100}SELECT\s.{0,100}\sFROM\s__InstanceModificationE/ nocase ascii wide
                        $string3_OffensiveNotion_offensive_tool_keyword = /\/OffensiveNotion\.git/ nocase ascii wide
                        $string4_OffensiveNotion_offensive_tool_keyword = "/OffensiveNotion/agent" nocase ascii wide
                        $string5_OffensiveNotion_offensive_tool_keyword = "/OffensiveNotion/osxcross/target/bin" nocase ascii wide
                        $string6_OffensiveNotion_offensive_tool_keyword = "/OffensiveNotion/utils"
                        $string7_OffensiveNotion_offensive_tool_keyword = "cddownloadelevategetprivsinjectpersistportscanpspwdrunassaveshellshutdownsleep" nocase ascii wide
                        $string8_OffensiveNotion_offensive_tool_keyword = "mttaggart/OffensiveNotion" nocase ascii wide
                        $string9_OffensiveNotion_offensive_tool_keyword = /offensive_notion\.exe/ nocase ascii wide
                        $string10_OffensiveNotion_offensive_tool_keyword = "offensive_notion_darwin_"
                        $string11_OffensiveNotion_offensive_tool_keyword = "offensive_notion_linux_"
                        $string12_OffensiveNotion_offensive_tool_keyword = /offensive_notion_win_.{0,100}\.exe/ nocase ascii wide
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