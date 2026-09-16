rule rule_remotemoe_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'remotemoe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "remotemoe"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_remotemoe_greyware_tool_keyword = /\sssh\s\-R.{0,100}\sremote\.moe/ nocase ascii wide
                        $string2_remotemoe_greyware_tool_keyword = /\.config\/systemd\/user\/remotemoe\.service/ nocase ascii wide
                        $string3_remotemoe_greyware_tool_keyword = /\/remotemoe\.git/ nocase ascii wide
                        $string4_remotemoe_greyware_tool_keyword = /159\.69\.126\.209/ nocase ascii wide
                        $string5_remotemoe_greyware_tool_keyword = "69bc5a68959f7b47ac43810dbe782723eca56101d4bb60533a78530ac1ba23b1" nocase ascii wide
                        $string6_remotemoe_greyware_tool_keyword = /7k3j6g3h67l23j345wennkoc4a2223rhjkba22o77ihzdj3achwa\.remote\.moe/ nocase ascii wide
                        $string7_remotemoe_greyware_tool_keyword = "92c70b09d49bef20ae730c579e125f4f7c66d85ef2249c77694f0066a3156b26" nocase ascii wide
                        $string8_remotemoe_greyware_tool_keyword = "df1b9ddfb57a7fa9b93b250a689e392171764364ff929a701e7a2df763904b78" nocase ascii wide
                        $string9_remotemoe_greyware_tool_keyword = /dummy\.remote\.moe/ nocase ascii wide
                        $string10_remotemoe_greyware_tool_keyword = "fasmide/remotemoe" nocase ascii wide
                        $string11_remotemoe_greyware_tool_keyword = /http\:\/\/.{0,100}\.remote\.moe\// nocase ascii wide
                        $string12_remotemoe_greyware_tool_keyword = /https\:\/\/.{0,100}\.remote\.moe\// nocase ascii wide
                        $string13_remotemoe_greyware_tool_keyword = /infrastructure\/remotemoe\.service/ nocase ascii wide
                        $string14_remotemoe_greyware_tool_keyword = "systemctl restart remotemoe" nocase ascii wide
                        $string15_remotemoe_greyware_tool_keyword = "systemctl start remotemoe" nocase ascii wide
                        $string16_remotemoe_greyware_tool_keyword = "systemctl status remotemoe" nocase ascii wide
                        $string17_remotemoe_greyware_tool_keyword = "systemctl stop remotemoe" nocase ascii wide
                        $string18_remotemoe_greyware_tool_keyword = /systemctl\s\-\-user\sstart\sremotemoe\.service/ nocase ascii wide
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