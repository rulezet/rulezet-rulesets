rule rule_action1_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'action1' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "action1"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_action1_greyware_tool_keyword = /\/action1_agent\(My_Organization\)\.msi/ nocase ascii wide
                        $string2_action1_greyware_tool_keyword = /\\Action1\\7z\.dll/ nocase ascii wide
                        $string3_action1_greyware_tool_keyword = /\\Action1\\Agent\\Certificate/ nocase ascii wide
                        $string4_action1_greyware_tool_keyword = /\\Action1\\CrashDumps/ nocase ascii wide
                        $string5_action1_greyware_tool_keyword = /\\Action1\\package_downloads/ nocase ascii wide
                        $string6_action1_greyware_tool_keyword = /\\Action1\\scripts\\Run_PowerShell_/ nocase ascii wide
                        $string7_action1_greyware_tool_keyword = /\\action1_agent\(My_Organization\)\.msi/ nocase ascii wide
                        $string8_action1_greyware_tool_keyword = /\\ACTION1_AGENT\.EXE\-/ nocase ascii wide
                        $string9_action1_greyware_tool_keyword = /\\action1_log_.{0,1000}\.log/ nocase ascii wide
                        $string10_action1_greyware_tool_keyword = /\\Windows\\Action1\\scripts\\/ nocase ascii wide
                        $string11_action1_greyware_tool_keyword = "_renamed_by_Action1" nocase ascii wide
                        $string12_action1_greyware_tool_keyword = /a1\-server\-prod\-even\.action1\.com/ nocase ascii wide
                        $string13_action1_greyware_tool_keyword = "Action1 Corporation" nocase ascii wide
                        $string14_action1_greyware_tool_keyword = "Action1 Endpoint Security" nocase ascii wide
                        $string15_action1_greyware_tool_keyword = /Action1.{0,1000}\'DestinationPort\'\>22543/ nocase ascii wide
                        $string16_action1_greyware_tool_keyword = /Action1\\batch_data\\Run_Script__/ nocase ascii wide
                        $string17_action1_greyware_tool_keyword = /Action1\\first_install\.tmp/ nocase ascii wide
                        $string18_action1_greyware_tool_keyword = /Action1\\what_is_this\.txt/ nocase ascii wide
                        $string19_action1_greyware_tool_keyword = /action1_agent\.exe/ nocase ascii wide
                        $string20_action1_greyware_tool_keyword = /action1_agent\.exe\.connection/ nocase ascii wide
                        $string21_action1_greyware_tool_keyword = /action1_remote\.exe/ nocase ascii wide
                        $string22_action1_greyware_tool_keyword = /action1_update\.exe/ nocase ascii wide
                        $string23_action1_greyware_tool_keyword = /C\:\\Windows\\Action1\\/ nocase ascii wide
                        $string24_action1_greyware_tool_keyword = /C\:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Action1/ nocase ascii wide
                        $string25_action1_greyware_tool_keyword = "'Company'>Action1 Corporation" nocase ascii wide
                        $string26_action1_greyware_tool_keyword = /CurrentControlSet\\Services\\A1Agent/ nocase ascii wide
                        $string27_action1_greyware_tool_keyword = /https\:\/\/app\.action1\.com\/agent\/.{0,1000}\/Windows\/.{0,1000}\.msi/ nocase ascii wide
                        $string28_action1_greyware_tool_keyword = /InventoryApplicationFile\\action1_agent\.ex/ nocase ascii wide
                        $string29_action1_greyware_tool_keyword = /InventoryApplicationFile\\action1_remote\.e/ nocase ascii wide
                        $string30_action1_greyware_tool_keyword = /server\.action1\.com/ nocase ascii wide

    condition:
        any of them
}