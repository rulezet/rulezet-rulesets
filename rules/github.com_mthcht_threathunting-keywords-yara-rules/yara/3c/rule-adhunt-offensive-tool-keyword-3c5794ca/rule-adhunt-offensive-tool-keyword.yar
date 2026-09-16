rule rule_adhunt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adhunt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adhunt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adhunt_offensive_tool_keyword = /\sadhunt\.py\s/ nocase ascii wide
                        $string2_adhunt_offensive_tool_keyword = /\/ADHunt\.git/ nocase ascii wide
                        $string3_adhunt_offensive_tool_keyword = /\/adhunt\.py/ nocase ascii wide
                        $string4_adhunt_offensive_tool_keyword = /\\adhunt\.py/ nocase ascii wide
                        $string5_adhunt_offensive_tool_keyword = /ad_dns_dump\.txt/ nocase ascii wide
                        $string6_adhunt_offensive_tool_keyword = /ADHunt\-main\.zip/ nocase ascii wide
                        $string7_adhunt_offensive_tool_keyword = /dcenum\.run/ nocase ascii wide
                        $string8_adhunt_offensive_tool_keyword = /delegation_constrained_objects\.txt/ nocase ascii wide
                        $string9_adhunt_offensive_tool_keyword = /delegation_constrained_w_protocol_transition_objects\.txt/ nocase ascii wide
                        $string10_adhunt_offensive_tool_keyword = /delegation_rbcd_objects\.txt/ nocase ascii wide
                        $string11_adhunt_offensive_tool_keyword = /delegation_unconstrained_objects\.txt/ nocase ascii wide
                        $string12_adhunt_offensive_tool_keyword = "karendm/ADHunt" nocase ascii wide
                        $string13_adhunt_offensive_tool_keyword = /objects_constrained_delegation_full\.txt/ nocase ascii wide
                        $string14_adhunt_offensive_tool_keyword = /objects_rbcd_delegation_full\.txt/ nocase ascii wide
                        $string15_adhunt_offensive_tool_keyword = /objects_unconstrained_delegation_full\.txt/ nocase ascii wide
                        $string16_adhunt_offensive_tool_keyword = /smbenum\.run/ nocase ascii wide
                        $string17_adhunt_offensive_tool_keyword = /users_asreproast\.txt/ nocase ascii wide
                        $string18_adhunt_offensive_tool_keyword = /users_dcsrp_full\.txt/ nocase ascii wide
                        $string19_adhunt_offensive_tool_keyword = /users_kerberoasting\.txt/ nocase ascii wide
                        $string20_adhunt_offensive_tool_keyword = /users_no_req_pass\.txt/ nocase ascii wide
                        $string21_adhunt_offensive_tool_keyword = /users_no_req_pass_full\.txt/ nocase ascii wide
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