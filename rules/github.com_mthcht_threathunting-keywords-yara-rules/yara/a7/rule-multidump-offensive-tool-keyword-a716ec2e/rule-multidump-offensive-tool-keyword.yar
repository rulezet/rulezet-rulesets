rule rule_MultiDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MultiDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MultiDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MultiDump_offensive_tool_keyword = /\sMultiDump\.exe/ nocase ascii wide
                        $string2_MultiDump_offensive_tool_keyword = /\.exe\s\-\-procdump\s\-p\s/ nocase ascii wide
                        $string3_MultiDump_offensive_tool_keyword = /\/MultiDump\.exe/ nocase ascii wide
                        $string4_MultiDump_offensive_tool_keyword = /\/MultiDump\.git/ nocase ascii wide
                        $string5_MultiDump_offensive_tool_keyword = /\[\!\]\sDumping\sLSASS\sRequires\sElevated\sPriviledges\!/ nocase ascii wide
                        $string6_MultiDump_offensive_tool_keyword = /\[\!\]\sFailed\sto\sCreate\sProcess\sto\sDump\sSAM/ nocase ascii wide
                        $string7_MultiDump_offensive_tool_keyword = /\[\!\]\sFailed\sto\sTransfer\sLSASS\sDump/ nocase ascii wide
                        $string8_MultiDump_offensive_tool_keyword = /\[\-\]\sUnable\sto\sRead\sLSASS\sDump/ nocase ascii wide
                        $string9_MultiDump_offensive_tool_keyword = /\[\+\]\sLSASS\sdump\sdone\!/ nocase ascii wide
                        $string10_MultiDump_offensive_tool_keyword = /\[\+\]\sLSASS\sDump\sRead\:\s/ nocase ascii wide
                        $string11_MultiDump_offensive_tool_keyword = /\[i\]\sDumping\sLSASS\sUsing\scomsvcs\.dll/ nocase ascii wide
                        $string12_MultiDump_offensive_tool_keyword = /\[i\]\sDumping\sLSASS\sUsing\sProcDump/ nocase ascii wide
                        $string13_MultiDump_offensive_tool_keyword = /\[i\]\sSending\sEncrypted\sSAM\sSave/ nocase ascii wide
                        $string14_MultiDump_offensive_tool_keyword = /\\lsass\.dmp/ nocase ascii wide
                        $string15_MultiDump_offensive_tool_keyword = /\\MultiDump\.c/ nocase ascii wide
                        $string16_MultiDump_offensive_tool_keyword = /\\MultiDump\.exe/ nocase ascii wide
                        $string17_MultiDump_offensive_tool_keyword = /\\MultiDump\.sln/ nocase ascii wide
                        $string18_MultiDump_offensive_tool_keyword = /\\MultiDump\.vcxproj/ nocase ascii wide
                        $string19_MultiDump_offensive_tool_keyword = "2C6D323A-B51F-47CB-AD37-972FD051D475" nocase ascii wide
                        $string20_MultiDump_offensive_tool_keyword = "7ce3b3c16cdaa2dfae51fbcf163ac75947127a9fd5e2d3c588480e3629345e8f" nocase ascii wide
                        $string21_MultiDump_offensive_tool_keyword = "90229D7D-5CC2-4C1E-80D3-4B7C7289B480" nocase ascii wide
                        $string22_MultiDump_offensive_tool_keyword = "encrypted LSASS dump" nocase ascii wide
                        $string23_MultiDump_offensive_tool_keyword = "Error parsing lsass dump with pypykatz" nocase ascii wide
                        $string24_MultiDump_offensive_tool_keyword = "lsassDumpRetryCount" nocase ascii wide
                        $string25_MultiDump_offensive_tool_keyword = /ProcDumpHandler\.py\s\-r\s/ nocase ascii wide
                        $string26_MultiDump_offensive_tool_keyword = /Public\\lsass\.dmp/ nocase ascii wide
                        $string27_MultiDump_offensive_tool_keyword = /pypykatz\.pypykatz/ nocase ascii wide
                        $string28_MultiDump_offensive_tool_keyword = /reg\.exe\sexport\sHKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion/ nocase ascii wide
                        $string29_MultiDump_offensive_tool_keyword = /reg\.exe\ssave\sHKLM\\/ nocase ascii wide
                        $string30_MultiDump_offensive_tool_keyword = "Xre0uS/MultiDump" nocase ascii wide

    condition:
        any of them
}