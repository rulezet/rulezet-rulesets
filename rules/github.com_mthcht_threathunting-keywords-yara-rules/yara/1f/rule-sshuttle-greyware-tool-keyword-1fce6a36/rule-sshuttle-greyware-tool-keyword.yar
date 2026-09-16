rule rule_sshuttle_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshuttle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshuttle"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_sshuttle_greyware_tool_keyword = " install sshuttle"
                        $string2_sshuttle_greyware_tool_keyword = " py39-sshuttle"
                        $string3_sshuttle_greyware_tool_keyword = " sshuttle:sshuttle "
                        $string4_sshuttle_greyware_tool_keyword = "/etc/sshuttle"
                        $string5_sshuttle_greyware_tool_keyword = "/home/sshuttle"
                        $string6_sshuttle_greyware_tool_keyword = /\/sshuttle\.git/
                        $string7_sshuttle_greyware_tool_keyword = /\/sshuttle\.py/
                        $string8_sshuttle_greyware_tool_keyword = "/sshuttle/tarball"
                        $string9_sshuttle_greyware_tool_keyword = "/sshuttle/zipball"
                        $string10_sshuttle_greyware_tool_keyword = "/tmp/sshuttle"
                        $string11_sshuttle_greyware_tool_keyword = "b86e9468c1470e3a3e776f5cab91a1cb79927743cfbc92535e753024611e8b4e" nocase ascii wide
                        $string12_sshuttle_greyware_tool_keyword = "net-proxy/sshuttle"
                        $string13_sshuttle_greyware_tool_keyword = "sshuttle -"
                        $string14_sshuttle_greyware_tool_keyword = /sshuttle\.cmdline/
                        $string15_sshuttle_greyware_tool_keyword = /sshuttle\.firewall/
                        $string16_sshuttle_greyware_tool_keyword = /sshuttle\.linux/
                        $string17_sshuttle_greyware_tool_keyword = /sshuttle\.methods\.socket/
                        $string18_sshuttle_greyware_tool_keyword = /sshuttle\.server/
                        $string19_sshuttle_greyware_tool_keyword = /sshuttle\.service/
                        $string20_sshuttle_greyware_tool_keyword = /sshuttle\.ssh/
                        $string21_sshuttle_greyware_tool_keyword = "sshuttle/sshuttle"
                        $string22_sshuttle_greyware_tool_keyword = "SSHUTTLE0001"
                        $string23_sshuttle_greyware_tool_keyword = /sudoers\.d\/sshuttle_auto/
                        $string24_sshuttle_greyware_tool_keyword = "systemctl start sshuttle"
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