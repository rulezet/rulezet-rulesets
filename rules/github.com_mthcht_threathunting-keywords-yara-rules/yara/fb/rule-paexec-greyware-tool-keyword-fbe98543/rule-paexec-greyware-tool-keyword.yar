rule rule_PAExec_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PAExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PAExec"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_PAExec_greyware_tool_keyword = /\s\-csrc\sC\:\\\\Windows\\\\notepad\.exe\s\-c\scmd\.exe/ nocase ascii wide
                        $string2_PAExec_greyware_tool_keyword = " PAExec service" nocase ascii wide
                        $string3_PAExec_greyware_tool_keyword = /\%SYSTEMROOT\%\\PAExec\-/ nocase ascii wide
                        $string4_PAExec_greyware_tool_keyword = /\/PAExec\.cpp/ nocase ascii wide
                        $string5_PAExec_greyware_tool_keyword = /\/paexec\.exe/ nocase ascii wide
                        $string6_PAExec_greyware_tool_keyword = /\/PAExec\.git/ nocase ascii wide
                        $string7_PAExec_greyware_tool_keyword = /\/paexec_eula\.txt/ nocase ascii wide
                        $string8_PAExec_greyware_tool_keyword = /\\PAExec\.cpp/ nocase ascii wide
                        $string9_PAExec_greyware_tool_keyword = /\\PAExec\.exe/ nocase ascii wide
                        $string10_PAExec_greyware_tool_keyword = /\\PAEXEC\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string11_PAExec_greyware_tool_keyword = /\\PAExec\.log/ nocase ascii wide
                        $string12_PAExec_greyware_tool_keyword = /\\paexec\.obj/ nocase ascii wide
                        $string13_PAExec_greyware_tool_keyword = /\\paexec\.pdb/ nocase ascii wide
                        $string14_PAExec_greyware_tool_keyword = /\\PAExec\.sln/ nocase ascii wide
                        $string15_PAExec_greyware_tool_keyword = /\\PAExec\\.{0,1000}\.exe/ nocase ascii wide
                        $string16_PAExec_greyware_tool_keyword = /\\paexec_eula\.txt/ nocase ascii wide
                        $string17_PAExec_greyware_tool_keyword = /\\PAExec_Move/ nocase ascii wide
                        $string18_PAExec_greyware_tool_keyword = /\\pipe\\PAExecErr/ nocase ascii wide
                        $string19_PAExec_greyware_tool_keyword = /\\pipe\\PAExecIn/ nocase ascii wide
                        $string20_PAExec_greyware_tool_keyword = /\\pipe\\PAExecOut/ nocase ascii wide
                        $string21_PAExec_greyware_tool_keyword = "2FEB96F5-08E6-48A3-B306-794277650A08" nocase ascii wide
                        $string22_PAExec_greyware_tool_keyword = "2FEB96F5-08E6-48A3-B306-794277650A08" nocase ascii wide
                        $string23_PAExec_greyware_tool_keyword = "Description'>PAExec Application" nocase ascii wide
                        $string24_PAExec_greyware_tool_keyword = "'Details'>paexec application" nocase ascii wide
                        $string25_PAExec_greyware_tool_keyword = "HINT: PAExec probably needs to be " nocase ascii wide
                        $string26_PAExec_greyware_tool_keyword = /paexec\s\\\\/ nocase ascii wide
                        $string27_PAExec_greyware_tool_keyword = "PAExec error waiting for app to exit" nocase ascii wide
                        $string28_PAExec_greyware_tool_keyword = "PAExec service " nocase ascii wide
                        $string29_PAExec_greyware_tool_keyword = "PAExec starting process" nocase ascii wide
                        $string30_PAExec_greyware_tool_keyword = "PAExec timed out waiting for app to exit" nocase ascii wide
                        $string31_PAExec_greyware_tool_keyword = /paexec\.exe\s\\\\/ nocase ascii wide
                        $string32_PAExec_greyware_tool_keyword = /PAExec\.exe\s\-u\s/ nocase ascii wide
                        $string33_PAExec_greyware_tool_keyword = /PAExec\-master\.zip/ nocase ascii wide
                        $string34_PAExec_greyware_tool_keyword = /poweradmin\.com\/PAExec/ nocase ascii wide
                        $string35_PAExec_greyware_tool_keyword = "poweradminllc/PAExec" nocase ascii wide

    condition:
        any of them
}