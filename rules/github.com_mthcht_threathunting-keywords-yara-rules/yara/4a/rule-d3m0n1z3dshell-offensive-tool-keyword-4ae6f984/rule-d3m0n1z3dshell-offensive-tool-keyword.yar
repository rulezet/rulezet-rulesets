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
                        $string22_D3m0n1z3dShell_offensive_tool_keyword = /dumpcreds.{0,1000}mimipenguin/
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

    condition:
        any of them
}