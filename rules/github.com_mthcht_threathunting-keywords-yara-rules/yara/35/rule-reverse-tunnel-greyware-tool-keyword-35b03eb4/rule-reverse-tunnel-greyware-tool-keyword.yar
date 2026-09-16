rule rule_reverse_tunnel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'reverse-tunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverse-tunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_reverse_tunnel_greyware_tool_keyword = /\srtun\-server\-windows\-amd64\.exe/ nocase ascii wide
                        $string2_reverse_tunnel_greyware_tool_keyword = /\srtun\-windows\-amd64\.exe/ nocase ascii wide
                        $string3_reverse_tunnel_greyware_tool_keyword = " Starting tunneling server" nocase ascii wide
                        $string4_reverse_tunnel_greyware_tool_keyword = /\/reverse\-tunnel\.git/ nocase ascii wide
                        $string5_reverse_tunnel_greyware_tool_keyword = "/reverse-tunnel/agent/cmd" nocase ascii wide
                        $string6_reverse_tunnel_greyware_tool_keyword = "/reverse-tunnel/server/service" nocase ascii wide
                        $string7_reverse_tunnel_greyware_tool_keyword = "/rtun-freebsd-amd64" nocase ascii wide
                        $string8_reverse_tunnel_greyware_tool_keyword = "/rtun-linux-amd64"
                        $string9_reverse_tunnel_greyware_tool_keyword = "/rtun-linux-arm64"
                        $string10_reverse_tunnel_greyware_tool_keyword = "/rtun-mac-amd64" nocase ascii wide
                        $string11_reverse_tunnel_greyware_tool_keyword = "/rtun-server-freebsd-amd64" nocase ascii wide
                        $string12_reverse_tunnel_greyware_tool_keyword = "/rtun-server-linux-amd64"
                        $string13_reverse_tunnel_greyware_tool_keyword = "/rtun-server-linux-arm64"
                        $string14_reverse_tunnel_greyware_tool_keyword = "/rtun-server-mac-amd64" nocase ascii wide
                        $string15_reverse_tunnel_greyware_tool_keyword = /\/rtun\-server\-windows\-amd64\.exe/ nocase ascii wide
                        $string16_reverse_tunnel_greyware_tool_keyword = /\/rtun\-windows\-amd64\.exe/ nocase ascii wide
                        $string17_reverse_tunnel_greyware_tool_keyword = /\\rtun\-server\-windows\-amd64\.exe/ nocase ascii wide
                        $string18_reverse_tunnel_greyware_tool_keyword = /\\rtun\-windows\-amd64\.exe/ nocase ascii wide
                        $string19_reverse_tunnel_greyware_tool_keyword = "0f5c329fa1e4abd3d1d2fbbd493d0dcf419bc33e1aa809ed55500481ed2ebe65" nocase ascii wide
                        $string20_reverse_tunnel_greyware_tool_keyword = "14d29e0f977fb74a925c9c2cab1ef3ed34eb6b35345b0af1645a64f6b85040f8" nocase ascii wide
                        $string21_reverse_tunnel_greyware_tool_keyword = "19529823b5d0e8b0c2a4cf5e67b825254efbd7568b7d6b204a220e684e3787d7" nocase ascii wide
                        $string22_reverse_tunnel_greyware_tool_keyword = "1ccedb3262e89f8d841a6c6b3ea5e8c5ef8fb42779168e5cc47ba1674be930f1" nocase ascii wide
                        $string23_reverse_tunnel_greyware_tool_keyword = "2e28d91e35ca1009d77fc67d36553730e785333ffc14cb8af621113571bd730b" nocase ascii wide
                        $string24_reverse_tunnel_greyware_tool_keyword = "2e4ce6b3a2e7019459a3f6cad24e07ee614c800a9d5b29c3d83f50fd758d1a93" nocase ascii wide
                        $string25_reverse_tunnel_greyware_tool_keyword = "397ac6bd1ffe2d8baf3c8e41307bb36339fa0f7a97e61b614d25ab85cb3b90a7" nocase ascii wide
                        $string26_reverse_tunnel_greyware_tool_keyword = "3b76d79a32202f1cdbae1e5ed949ee7a75f373a9280fbdfd15a6cc4490a1b595" nocase ascii wide
                        $string27_reverse_tunnel_greyware_tool_keyword = "3e62062061ddd7a0974eb2f6106dc96d3c54f95f41121ff355de12d5a23e2624" nocase ascii wide
                        $string28_reverse_tunnel_greyware_tool_keyword = "411b16657e992717f0eb9ac77b2a5468e23afcc8747bdabba4bcdfc008c845e7" nocase ascii wide
                        $string29_reverse_tunnel_greyware_tool_keyword = "512fba960ac745dbb62576225ee9dd7f65bf83261c8d1364f50101c8e3fd55bf" nocase ascii wide
                        $string30_reverse_tunnel_greyware_tool_keyword = "5e47aac7b50d8ac6ce9ebba6c28ca58ef1332493fba47ab47ec1d2da61c7f6e2" nocase ascii wide
                        $string31_reverse_tunnel_greyware_tool_keyword = "6ab324b655ea1c39c3c8fb5709f322f0c468a203411fbbcb460b36ee0fc1d835" nocase ascii wide
                        $string32_reverse_tunnel_greyware_tool_keyword = "6f94077fc6f9092d9e9282bee1588e70aaf70ad90407e2bd164c38325249af5e" nocase ascii wide
                        $string33_reverse_tunnel_greyware_tool_keyword = "774dbc75e046096a7a18dbcef9353543db74312e9656ff4017d7f41c778be2fb" nocase ascii wide
                        $string34_reverse_tunnel_greyware_tool_keyword = "793e227ee3a811a143e303909645a874c8db144cf6b48f480411efb2fdd44904" nocase ascii wide
                        $string35_reverse_tunnel_greyware_tool_keyword = "8fd62fc653cef0bf765a71cf20a917c8440689e9f5ff77e95a5fea7be6818c66" nocase ascii wide
                        $string36_reverse_tunnel_greyware_tool_keyword = "955854f00a41ee91d047e520aa445035d881f9cb214de1ed49fac829e1caf829" nocase ascii wide
                        $string37_reverse_tunnel_greyware_tool_keyword = "a522a8bfbf83bf52cde85edb32577d6b9acddac6e3a432726f659ae7dd5a6a96" nocase ascii wide
                        $string38_reverse_tunnel_greyware_tool_keyword = "a79a4c3ae4ecd33b7c078631d3424137ff332d7897ecd6e9ddee28df138a0064" nocase ascii wide
                        $string39_reverse_tunnel_greyware_tool_keyword = "a8ebccf2cc342e1b5154989cd784691b5740a7f3df77cd8adb785f67384a93de" nocase ascii wide
                        $string40_reverse_tunnel_greyware_tool_keyword = "ba65a4a428b16812cfade65b50138e0b865496a637bdf5dad7993bf3907cdd60" nocase ascii wide
                        $string41_reverse_tunnel_greyware_tool_keyword = "d66a79fcbac667d28014c15003770a35bd941c346e87fb8e4e1b7fd02c3291c9" nocase ascii wide
                        $string42_reverse_tunnel_greyware_tool_keyword = "d71bbdd588cd4f1507ea794ed63be80a7cb3bbb1d30430150dd8800adec83fd5" nocase ascii wide
                        $string43_reverse_tunnel_greyware_tool_keyword = "d7eceeb90b1e75b17c42c6cef5b42e0ef1dc615efba9424bafce718304c7ee43" nocase ascii wide
                        $string44_reverse_tunnel_greyware_tool_keyword = "dec51bba37da4ecf4df8994cb21931fdfcc4f661c362cb8392f44229d42ef337" nocase ascii wide
                        $string45_reverse_tunnel_greyware_tool_keyword = "e6c9ef3c9ee804ca3bed5f13f5e179f9ef16b7b2513cdfc33974902faa0f7516" nocase ascii wide
                        $string46_reverse_tunnel_greyware_tool_keyword = "e717e4a46f338480838e760a05b7a628ccca57b0d4d705a67359bf9481fa58ae" nocase ascii wide
                        $string47_reverse_tunnel_greyware_tool_keyword = "ef77dea20926b6f460844b5a51fd0d238976a1dba89f20f0fccff96712ad9df8" nocase ascii wide
                        $string48_reverse_tunnel_greyware_tool_keyword = "f865ac0b99a90f54ce67bbabb2e57226a5c61f58e7a867598a3d54fdfee895ee" nocase ascii wide
                        $string49_reverse_tunnel_greyware_tool_keyword = "f99a0080be86f97331ea300f2a4f448097c5ae39100b15202c89fc91024b215e" nocase ascii wide
                        $string50_reverse_tunnel_greyware_tool_keyword = "snsinfu/reverse-tunnel" nocase ascii wide
                        $string51_reverse_tunnel_greyware_tool_keyword = /Tunneling\sremote\sconnection\sfrom\s.{0,100}\sto\s/ nocase ascii wide
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