rule rule_D3m0n1z3dShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'D3m0n1z3dShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "D3m0n1z3dShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_D3m0n1z3dShell_offensive_tool_keyword = /\.bashrc\spersistence\ssetup\ssuccessfully/
                        $string2_D3m0n1z3dShell_offensive_tool_keyword = "/chisel_x32"
                        $string3_D3m0n1z3dShell_offensive_tool_keyword = "/chisel_x64"
                        $string4_D3m0n1z3dShell_offensive_tool_keyword = /\/D3m0n1z3dShell\.git/
                        $string5_D3m0n1z3dShell_offensive_tool_keyword = "/D3m0n1z3dShell/archive/"
                        $string6_D3m0n1z3dShell_offensive_tool_keyword = /\/deepce\.sh/
                        $string7_D3m0n1z3dShell_offensive_tool_keyword = /\/install_locutus\.sh/
                        $string8_D3m0n1z3dShell_offensive_tool_keyword = /\/linpeas\.sh/
                        $string9_D3m0n1z3dShell_offensive_tool_keyword = "/tmp/borg_d3monized"
                        $string10_D3m0n1z3dShell_offensive_tool_keyword = /\/tmp\/tmpfolder\/pingoor\.c/
                        $string11_D3m0n1z3dShell_offensive_tool_keyword = /\/tmp\/tmpfolder\/pingoor\.h/
                        $string12_D3m0n1z3dShell_offensive_tool_keyword = /\[D3m0niz3d\]\~\#/
                        $string13_D3m0n1z3dShell_offensive_tool_keyword = /\\chisel_x32/
                        $string14_D3m0n1z3dShell_offensive_tool_keyword = /\\chisel_x64/
                        $string15_D3m0n1z3dShell_offensive_tool_keyword = "addPreloadToPrivesc"
                        $string16_D3m0n1z3dShell_offensive_tool_keyword = "bashRCPersistence"
                        $string17_D3m0n1z3dShell_offensive_tool_keyword = "D3m0n1z3dShell-main"
                        $string18_D3m0n1z3dShell_offensive_tool_keyword = /deepce\.sh\s\-e\s/
                        $string19_D3m0n1z3dShell_offensive_tool_keyword = /demonizedshell\.sh/
                        $string20_D3m0n1z3dShell_offensive_tool_keyword = /demonizedshell_static\.sh/
                        $string21_D3m0n1z3dShell_offensive_tool_keyword = "discovery_port_scan"
                        $string22_D3m0n1z3dShell_offensive_tool_keyword = /dumpcreds.{0,100}mimipenguin/
                        $string23_D3m0n1z3dShell_offensive_tool_keyword = "I2lmbmRlZiBQSU5HT09SCiNkZWZpbmUgUElOR09PUgoKI2RlZmluZSBTRVJWRVJJUCAiM"
                        $string24_D3m0n1z3dShell_offensive_tool_keyword = "icmpBackdoor"
                        $string25_D3m0n1z3dShell_offensive_tool_keyword = /implant_rootkit\.sh/
                        $string26_D3m0n1z3dShell_offensive_tool_keyword = "lkmRootkitmodified"
                        $string27_D3m0n1z3dShell_offensive_tool_keyword = "MatheuZSecurity/D3m0n1z3dShell"
                        $string28_D3m0n1z3dShell_offensive_tool_keyword = /mimipenguin\.py/
                        $string29_D3m0n1z3dShell_offensive_tool_keyword = /mimipenguin\.sh/
                        $string30_D3m0n1z3dShell_offensive_tool_keyword = "MotdPersistence"
                        $string31_D3m0n1z3dShell_offensive_tool_keyword = /pwd\|passwd\|password\|PASSWD\|PASSWORD\|dbuser\|dbpass\|pass/
                        $string32_D3m0n1z3dShell_offensive_tool_keyword = "su_brute_user_num"
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