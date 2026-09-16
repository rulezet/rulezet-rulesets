rule rule_PWDumpX_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PWDumpX' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PWDumpX"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PWDumpX_offensive_tool_keyword = /\sDumpSvc\.exe/ nocase ascii wide
                        $string2_PWDumpX_offensive_tool_keyword = " PWDumpX process " nocase ascii wide
                        $string3_PWDumpX_offensive_tool_keyword = " PWDumpX service " nocase ascii wide
                        $string4_PWDumpX_offensive_tool_keyword = /\/DumpSvc\.exe/ nocase ascii wide
                        $string5_PWDumpX_offensive_tool_keyword = /\\DumpExt\.dll/ nocase ascii wide
                        $string6_PWDumpX_offensive_tool_keyword = /\\DumpSvc\.exe/ nocase ascii wide
                        $string7_PWDumpX_offensive_tool_keyword = /\\LSASecrets\.txt/ nocase ascii wide
                        $string8_PWDumpX_offensive_tool_keyword = /\\PWDumpX\.c/ nocase ascii wide
                        $string9_PWDumpX_offensive_tool_keyword = /\\PWHashes\.txt/ nocase ascii wide
                        $string10_PWDumpX_offensive_tool_keyword = /\\services\\PWDumpX\\/ nocase ascii wide
                        $string11_PWDumpX_offensive_tool_keyword = "_DumpLSASecrets" nocase ascii wide
                        $string12_PWDumpX_offensive_tool_keyword = ">PWDumpX Service<" nocase ascii wide
                        $string13_PWDumpX_offensive_tool_keyword = "12e55226b801ebdfcc9334ca438a57db1da463de48e2893009a7bb3e5e5e0dbc" nocase ascii wide
                        $string14_PWDumpX_offensive_tool_keyword = "3f5ea2764696b07fdb61c7b34736eae26518ed2e36a624df09fb37025659201f" nocase ascii wide
                        $string15_PWDumpX_offensive_tool_keyword = "3f5ea2764696b07fdb61c7b34736eae26518ed2e36a624df09fb37025659201f" nocase ascii wide
                        $string16_PWDumpX_offensive_tool_keyword = "52b9c0a0a0188e47cb4b812aabe5a1832633fe9d66cebf702dfe0de114db0abd" nocase ascii wide
                        $string17_PWDumpX_offensive_tool_keyword = "5c85b965c19ff7f7742980f90965279aa0ae2ea4c50317ad7680b56d6e3ed9d5" nocase ascii wide
                        $string18_PWDumpX_offensive_tool_keyword = "78b4ff5e1bbac4a8bde265705a5c6e36b41bb2a9170f8f060a09bb1552549af2" nocase ascii wide
                        $string19_PWDumpX_offensive_tool_keyword = "79c1d4ab8f425095d2d9f2a18a0cab08d31b686b149fba3db24a13e2bc7299ee" nocase ascii wide
                        $string20_PWDumpX_offensive_tool_keyword = "80a9520b464f4bd7b4747c897a66a3c41a9100cb9efcd94614e2bd053247285a" nocase ascii wide
                        $string21_PWDumpX_offensive_tool_keyword = "Cannot enable SE_DEBUG_NAME privilege on remote host" nocase ascii wide
                        $string22_PWDumpX_offensive_tool_keyword = "Cannot get LSASS PID on remote host" nocase ascii wide
                        $string23_PWDumpX_offensive_tool_keyword = "Cannot load SAM functions on remote host" nocase ascii wide
                        $string24_PWDumpX_offensive_tool_keyword = "Cannot open LSA policy on remote host" nocase ascii wide
                        $string25_PWDumpX_offensive_tool_keyword = /Cannot\sopen\sregistry\skey\sHKLM\\SECURITY\\Policy\\Secrets\son\sremote\shost/ nocase ascii wide
                        $string26_PWDumpX_offensive_tool_keyword = "Cannot open SAM on remote host" nocase ascii wide
                        $string27_PWDumpX_offensive_tool_keyword = /https\:\/\/reedarvin\.thearvins\.com\// nocase ascii wide
                        $string28_PWDumpX_offensive_tool_keyword = "-LIBGCCW32-EH-3-SJLJ-GTHR-MINGW32" nocase ascii wide
                        $string29_PWDumpX_offensive_tool_keyword = /\-LSASecrets\.txt/ nocase ascii wide
                        $string30_PWDumpX_offensive_tool_keyword = "PWDumpDLLPath" nocase ascii wide
                        $string31_PWDumpX_offensive_tool_keyword = "PWDumpEXEPath" nocase ascii wide
                        $string32_PWDumpX_offensive_tool_keyword = "PWDumpX " nocase ascii wide
                        $string33_PWDumpX_offensive_tool_keyword = /PWDumpX\sv1\.0/ nocase ascii wide
                        $string34_PWDumpX_offensive_tool_keyword = /PWDumpX\.zip/ nocase ascii wide
                        $string35_PWDumpX_offensive_tool_keyword = /\-PWHashes\.txt/ nocase ascii wide
                        $string36_PWDumpX_offensive_tool_keyword = /reedarvin\@gmail\.com/ nocase ascii wide
                        $string37_PWDumpX_offensive_tool_keyword = "szRemotePWDumpEXEPath" nocase ascii wide

    condition:
        any of them
}