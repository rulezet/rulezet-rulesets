rule rule__0d1n_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '0d1n' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "0d1n"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1__0d1n_offensive_tool_keyword = /\/0d1n\.c/ nocase ascii wide
                        $string2__0d1n_offensive_tool_keyword = "/0d1n_view" nocase ascii wide
                        $string3__0d1n_offensive_tool_keyword = "/bin/0d1n"
                        $string4__0d1n_offensive_tool_keyword = /\/crlfinjection\.txt/ nocase ascii wide
                        $string5__0d1n_offensive_tool_keyword = /\/dir_brute\.txt/ nocase ascii wide
                        $string6__0d1n_offensive_tool_keyword = /\/js_inject\.txt/ nocase ascii wide
                        $string7__0d1n_offensive_tool_keyword = /\/ldap_injection\.txt/ nocase ascii wide
                        $string8__0d1n_offensive_tool_keyword = /\/passive_sqli\.txt/ nocase ascii wide
                        $string9__0d1n_offensive_tool_keyword = /\/password_brute\.txt/ nocase ascii wide
                        $string10__0d1n_offensive_tool_keyword = /\/path_traversal\.txt/ nocase ascii wide
                        $string11__0d1n_offensive_tool_keyword = /\/path_traversal_win32\.txt/ nocase ascii wide
                        $string12__0d1n_offensive_tool_keyword = /\/sqli\.txt/ nocase ascii wide
                        $string13__0d1n_offensive_tool_keyword = /\/xml_attack\.txt/ nocase ascii wide
                        $string14__0d1n_offensive_tool_keyword = /\/xml_attacks\.txt/ nocase ascii wide
                        $string15__0d1n_offensive_tool_keyword = /\/xpath_injection\.txt/ nocase ascii wide
                        $string16__0d1n_offensive_tool_keyword = /\/xss_robertux\.txt/ nocase ascii wide
                        $string17__0d1n_offensive_tool_keyword = /\/xxe_fuzz\.txt/ nocase ascii wide
                        $string18__0d1n_offensive_tool_keyword = /0d1n\s.{0,100}\s\-\-post\s.{0,100}\s\-\-payloads\s/ nocase ascii wide
                        $string19__0d1n_offensive_tool_keyword = "0d1n --host" nocase ascii wide
                        $string20__0d1n_offensive_tool_keyword = /0d1n.{0,100}kill_listener\.sh/ nocase ascii wide
                        $string21__0d1n_offensive_tool_keyword = "CoolerVoid/0d1n" nocase ascii wide
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