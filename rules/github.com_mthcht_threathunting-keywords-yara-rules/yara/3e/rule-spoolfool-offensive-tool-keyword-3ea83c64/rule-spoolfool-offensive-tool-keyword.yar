rule rule_SpoolFool_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SpoolFool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpoolFool"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SpoolFool_offensive_tool_keyword = /\s\-dll\sadd_user\.dll\s\-dir\s/ nocase ascii wide
                        $string2_SpoolFool_offensive_tool_keyword = /\s\-dll\sadd_user\.dll\s\-printer\s/ nocase ascii wide
                        $string3_SpoolFool_offensive_tool_keyword = /\sSpoolFool\.ps1/ nocase ascii wide
                        $string4_SpoolFool_offensive_tool_keyword = /\/SpoolFool\.exe/ nocase ascii wide
                        $string5_SpoolFool_offensive_tool_keyword = /\/SpoolFool\.git/ nocase ascii wide
                        $string6_SpoolFool_offensive_tool_keyword = /\/SpoolFool\.ps1/ nocase ascii wide
                        $string7_SpoolFool_offensive_tool_keyword = /\[\+\]\sSuccessfully\sset\sthe\sspool\sdirectory\sto\:\s/ nocase ascii wide
                        $string8_SpoolFool_offensive_tool_keyword = /\\AddUser\.dll/ nocase ascii wide
                        $string9_SpoolFool_offensive_tool_keyword = /\\AddUser\.sln/ nocase ascii wide
                        $string10_SpoolFool_offensive_tool_keyword = /\\Release\\SpoolFool\.pdb/ nocase ascii wide
                        $string11_SpoolFool_offensive_tool_keyword = /\\SpoolFool\.exe/ nocase ascii wide
                        $string12_SpoolFool_offensive_tool_keyword = /\\SpoolFool\.ps1/ nocase ascii wide
                        $string13_SpoolFool_offensive_tool_keyword = /\\SpoolFool\.sln/ nocase ascii wide
                        $string14_SpoolFool_offensive_tool_keyword = /\\SpoolFool\-main/ nocase ascii wide
                        $string15_SpoolFool_offensive_tool_keyword = /\]\sGranting\sread\sand\sexecute\sto\sSYSTEM\son\sDLL\:\s/ nocase ascii wide
                        $string16_SpoolFool_offensive_tool_keyword = "11a92a7c6a84715416eb8a1c033a6a8db9a70494bfc08c9f09734e599be76cef" nocase ascii wide
                        $string17_SpoolFool_offensive_tool_keyword = "4c7714ee-c58d-4ef7-98f2-b162baec0ee0" nocase ascii wide
                        $string18_SpoolFool_offensive_tool_keyword = "4f715f37eddadb3d8f5680f7075e695e99496b91473f17d4507568518dd4284d" nocase ascii wide
                        $string19_SpoolFool_offensive_tool_keyword = "50388787c5a5da5c25ca1f6bfdaf3f09c3c78d9f0306e87b7e7d191bf679d870" nocase ascii wide
                        $string20_SpoolFool_offensive_tool_keyword = "69ab4c2375c28b0520090c3ce7c3f033d5429aee8a0ef2f7b5f54edee2a759b7" nocase ascii wide
                        $string21_SpoolFool_offensive_tool_keyword = "7cd4a538c3d1242ede7dcbea8dfdba84031e232e4327ed3c89292714032da91c" nocase ascii wide
                        $string22_SpoolFool_offensive_tool_keyword = "b979225195d70240e32deae75233b82e05ceb32bab4d08d970399065fba8ea88" nocase ascii wide
                        $string23_SpoolFool_offensive_tool_keyword = "c0a7a797f39b509fd2d895b5731e79b57b350b85b20be5a51c0a1bda19321bd0" nocase ascii wide
                        $string24_SpoolFool_offensive_tool_keyword = "e347df6964e8d7ac73e12d28773f260a80109fb1049bc106ae90800381927cee" nocase ascii wide
                        $string25_SpoolFool_offensive_tool_keyword = "EC49A1B1-4DAA-47B1-90D1-787D44C641C0" nocase ascii wide
                        $string26_SpoolFool_offensive_tool_keyword = "Invoke-SpoolFool" nocase ascii wide
                        $string27_SpoolFool_offensive_tool_keyword = "ly4k/SpoolFool" nocase ascii wide

    condition:
        any of them
}