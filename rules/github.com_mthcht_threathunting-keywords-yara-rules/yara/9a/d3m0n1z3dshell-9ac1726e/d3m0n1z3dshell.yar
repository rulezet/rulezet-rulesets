rule D3m0n1z3dShell
{
    meta:
        description = "Detection patterns for the tool 'D3m0n1z3dShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "D3m0n1z3dShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.bashrc\spersistence\ssetup\ssuccessfully/
                        $string2 = "/chisel_x32"
                        $string3 = "/chisel_x64"
                        $string4 = /\/D3m0n1z3dShell\.git/
                        $string5 = "/D3m0n1z3dShell/archive/"
                        $string6 = /\/deepce\.sh/
                        $string7 = /\/install_locutus\.sh/
                        $string8 = /\/linpeas\.sh/
                        $string9 = "/tmp/borg_d3monized"
                        $string10 = /\/tmp\/tmpfolder\/pingoor\.c/
                        $string11 = /\/tmp\/tmpfolder\/pingoor\.h/
                        $string12 = /\[D3m0niz3d\]\~\#/
                        $string13 = /\\chisel_x32/
                        $string14 = /\\chisel_x64/
                        $string15 = "addPreloadToPrivesc"
                        $string16 = "bashRCPersistence"
                        $string17 = "D3m0n1z3dShell-main"
                        $string18 = /deepce\.sh\s\-e\s/
                        $string19 = /demonizedshell\.sh/
                        $string20 = /demonizedshell_static\.sh/
                        $string21 = "discovery_port_scan"
                        $string22 = /dumpcreds.{0,100}mimipenguin/
                        $string23 = "I2lmbmRlZiBQSU5HT09SCiNkZWZpbmUgUElOR09PUgoKI2RlZmluZSBTRVJWRVJJUCAiM"
                        $string24 = "icmpBackdoor"
                        $string25 = /implant_rootkit\.sh/
                        $string26 = "lkmRootkitmodified"
                        $string27 = "MatheuZSecurity/D3m0n1z3dShell"
                        $string28 = /mimipenguin\.py/
                        $string29 = /mimipenguin\.sh/
                        $string30 = "MotdPersistence"
                        $string31 = /pwd\|passwd\|password\|PASSWD\|PASSWORD\|dbuser\|dbpass\|pass/
                        $string32 = "su_brute_user_num"
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