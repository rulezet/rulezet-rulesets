rule rule_RustDesk_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RustDesk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustDesk"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_RustDesk_greyware_tool_keyword = /\sRustDesk\.exe/ nocase ascii wide
                        $string2_RustDesk_greyware_tool_keyword = " start rustdesk://" nocase ascii wide
                        $string3_RustDesk_greyware_tool_keyword = "/home/user/rustdesk"
                        $string4_RustDesk_greyware_tool_keyword = /\/RustDesk\.exe/ nocase ascii wide
                        $string5_RustDesk_greyware_tool_keyword = /\/rustdesk\.git/ nocase ascii wide
                        $string6_RustDesk_greyware_tool_keyword = "/rustdesk/rustdesk/releases/" nocase ascii wide
                        $string7_RustDesk_greyware_tool_keyword = /\\\.rustdesk/ nocase ascii wide
                        $string8_RustDesk_greyware_tool_keyword = /\\\\RustDeskIddDriver/ nocase ascii wide
                        $string9_RustDesk_greyware_tool_keyword = /\\AppData\\Local\\rustdesk\\/ nocase ascii wide
                        $string10_RustDesk_greyware_tool_keyword = /\\config\\RustDesk\.toml/ nocase ascii wide
                        $string11_RustDesk_greyware_tool_keyword = /\\config\\RustDesk_local\./ nocase ascii wide
                        $string12_RustDesk_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\RustDesk/ nocase ascii wide
                        $string13_RustDesk_greyware_tool_keyword = /\\librustdesk\.dll/ nocase ascii wide
                        $string14_RustDesk_greyware_tool_keyword = /\\ProgramData\\RustDesk\\/ nocase ascii wide
                        $string15_RustDesk_greyware_tool_keyword = /\\rustdesk\-.{0,1000}\-x86_64\.exe/ nocase ascii wide
                        $string16_RustDesk_greyware_tool_keyword = /\\RustDesk\.exe/ nocase ascii wide
                        $string17_RustDesk_greyware_tool_keyword = /\\RustDesk\.lnk/ nocase ascii wide
                        $string18_RustDesk_greyware_tool_keyword = /\\RustDesk\\query/ nocase ascii wide
                        $string19_RustDesk_greyware_tool_keyword = /\\RustDeskIddDriver\\/ nocase ascii wide
                        $string20_RustDesk_greyware_tool_keyword = /\\test_rustdesk\.log/ nocase ascii wide
                        $string21_RustDesk_greyware_tool_keyword = "095e73fc4b115afd77e39a9389ff1eff6bdbff7a" nocase ascii wide
                        $string22_RustDesk_greyware_tool_keyword = /HKEY_CLASSES_ROOT\\rustdesk/ nocase ascii wide
                        $string23_RustDesk_greyware_tool_keyword = /info\@rustdesk\.com/ nocase ascii wide
                        $string24_RustDesk_greyware_tool_keyword = "name=\"RustDesk Service\"" nocase ascii wide
                        $string25_RustDesk_greyware_tool_keyword = /rs\-ny\.rustdesk\.com/ nocase ascii wide
                        $string26_RustDesk_greyware_tool_keyword = /RuntimeBroker_rustdesk\.exe/ nocase ascii wide
                        $string27_RustDesk_greyware_tool_keyword = "RustDesk Service is running" nocase ascii wide
                        $string28_RustDesk_greyware_tool_keyword = /rustdesk\-.{0,1000}\.apk/ nocase ascii wide
                        $string29_RustDesk_greyware_tool_keyword = /rustdesk\-.{0,1000}\.deb/ nocase ascii wide
                        $string30_RustDesk_greyware_tool_keyword = /rustdesk\-.{0,1000}\.dmg/ nocase ascii wide
                        $string31_RustDesk_greyware_tool_keyword = /rustdesk\-.{0,1000}\.rpm/ nocase ascii wide
                        $string32_RustDesk_greyware_tool_keyword = /rustdesk\-.{0,1000}\-win7\-install\.exe/ nocase ascii wide
                        $string33_RustDesk_greyware_tool_keyword = /RustDesk\.exe\s/ nocase ascii wide
                        $string34_RustDesk_greyware_tool_keyword = /RUSTDESK\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string35_RustDesk_greyware_tool_keyword = /RustDesk_hwcodec\./ nocase ascii wide
                        $string36_RustDesk_greyware_tool_keyword = /RustDesk_install\.bat/ nocase ascii wide
                        $string37_RustDesk_greyware_tool_keyword = /rustdesk_portable\.exe/ nocase ascii wide
                        $string38_RustDesk_greyware_tool_keyword = /RustDesk_rCURRENT\.log/ nocase ascii wide
                        $string39_RustDesk_greyware_tool_keyword = /RustDesk_uninstall\.bat/ nocase ascii wide
                        $string40_RustDesk_greyware_tool_keyword = /RustDeskIddDriver\.cer/ nocase ascii wide
                        $string41_RustDesk_greyware_tool_keyword = /RustDeskIddDriver\.dll/ nocase ascii wide
                        $string42_RustDesk_greyware_tool_keyword = /rustdesk\-portable\-packer\.exe/ nocase ascii wide
                        $string43_RustDesk_greyware_tool_keyword = "sc start RustDesk" nocase ascii wide
                        $string44_RustDesk_greyware_tool_keyword = "sc stop RustDesk" nocase ascii wide

    condition:
        any of them
}