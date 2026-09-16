rule rule_MEGAsync_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MEGAsync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MEGAsync"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_MEGAsync_greyware_tool_keyword = /\smegasync\.exe/ nocase ascii wide
                        $string2_MEGAsync_greyware_tool_keyword = /\sMEGAsyncSetup32\.exe/ nocase ascii wide
                        $string3_MEGAsync_greyware_tool_keyword = /\sMEGAsyncSetup64\.exe/ nocase ascii wide
                        $string4_MEGAsync_greyware_tool_keyword = /\.api\.mega\.co\.nz/ nocase ascii wide
                        $string5_MEGAsync_greyware_tool_keyword = /\.static\.mega\.co\.nz/ nocase ascii wide
                        $string6_MEGAsync_greyware_tool_keyword = /\/megasync\.exe/ nocase ascii wide
                        $string7_MEGAsync_greyware_tool_keyword = /\/MEGAsyncSetup32\.exe/ nocase ascii wide
                        $string8_MEGAsync_greyware_tool_keyword = /\/MEGAsyncSetup64\.exe/ nocase ascii wide
                        $string9_MEGAsync_greyware_tool_keyword = /\[megaapi_impl\.cpp\:/ nocase ascii wide
                        $string10_MEGAsync_greyware_tool_keyword = /\[megaclient\.cpp\:/ nocase ascii wide
                        $string11_MEGAsync_greyware_tool_keyword = /\\appdata\\local\\megasync\\/ nocase ascii wide
                        $string12_MEGAsync_greyware_tool_keyword = /\\ContextMenuHandlers\\MEGA\s\(Context\smenu\)/ nocase ascii wide
                        $string13_MEGAsync_greyware_tool_keyword = /\\CurrentVersion\\App\sPaths\\MEGAsync/ nocase ascii wide
                        $string14_MEGAsync_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\MEGAsync/ nocase ascii wide
                        $string15_MEGAsync_greyware_tool_keyword = /\\MEGA\sWebsite\.lnk/ nocase ascii wide
                        $string16_MEGAsync_greyware_tool_keyword = /\\MEGA\sWebsite\.url/ nocase ascii wide
                        $string17_MEGAsync_greyware_tool_keyword = /\\megaclient_statecache.{0,1000}\.db/ nocase ascii wide
                        $string18_MEGAsync_greyware_tool_keyword = /\\megaclient_syncconfig_/ nocase ascii wide
                        $string19_MEGAsync_greyware_tool_keyword = /\\megalimited\-megasync_/ nocase ascii wide
                        $string20_MEGAsync_greyware_tool_keyword = /\\MEGAprivacyMEGAsync/ nocase ascii wide
                        $string21_MEGAsync_greyware_tool_keyword = /\\MEGAsync\.cfg/ nocase ascii wide
                        $string22_MEGAsync_greyware_tool_keyword = /\\megasync\.exe/ nocase ascii wide
                        $string23_MEGAsync_greyware_tool_keyword = /\\MEGAsync\.lnk/ nocase ascii wide
                        $string24_MEGAsync_greyware_tool_keyword = /\\megasync\.lock/ nocase ascii wide
                        $string25_MEGAsync_greyware_tool_keyword = /\\MEGAsync\.log/ nocase ascii wide
                        $string26_MEGAsync_greyware_tool_keyword = /\\megasync\.version/ nocase ascii wide
                        $string27_MEGAsync_greyware_tool_keyword = /\\MEGAsyncSetup32\.exe/ nocase ascii wide
                        $string28_MEGAsync_greyware_tool_keyword = /\\MEGAsyncSetup64\.exe/ nocase ascii wide
                        $string29_MEGAsync_greyware_tool_keyword = /\\MEGAupdater\.exe/ nocase ascii wide
                        $string30_MEGAsync_greyware_tool_keyword = /\\ProgramData\\megatmp\.M1\.txt/ nocase ascii wide
                        $string31_MEGAsync_greyware_tool_keyword = /\\ProgramData\\megatmp\.M2\.txt/ nocase ascii wide
                        $string32_MEGAsync_greyware_tool_keyword = /\\ShellIconOverlayIdentifiers\\_\sMEGA\s\(Pending\)/ nocase ascii wide
                        $string33_MEGAsync_greyware_tool_keyword = /\\ShellIconOverlayIdentifiers\\_\sMEGA\s\(Synced\)/ nocase ascii wide
                        $string34_MEGAsync_greyware_tool_keyword = /\\ShellIconOverlayIdentifiers\\_\sMEGA\s\(Syncing\)/ nocase ascii wide
                        $string35_MEGAsync_greyware_tool_keyword = /\\Start\sMenu\\Programs\\MEGAsync\\/ nocase ascii wide
                        $string36_MEGAsync_greyware_tool_keyword = /\\StartupTNotiMEGAsync\.lnk/ nocase ascii wide
                        $string37_MEGAsync_greyware_tool_keyword = "'Company'>Mega Limited</Data>" nocase ascii wide
                        $string38_MEGAsync_greyware_tool_keyword = /https\:\/\/mega\.nz\/linux\/repo\//
                        $string39_MEGAsync_greyware_tool_keyword = "MEGAsync Update Task" nocase ascii wide
                        $string40_MEGAsync_greyware_tool_keyword = /MEGAsync\.exe\s\// nocase ascii wide
                        $string41_MEGAsync_greyware_tool_keyword = /MEGASYNC\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string42_MEGAsync_greyware_tool_keyword = /MEGAsync\\ShellExtX64\.dll/ nocase ascii wide
                        $string43_MEGAsync_greyware_tool_keyword = /megasync\-CentOS_.{0,1000}\.x86_64\.rpm/ nocase ascii wide
                        $string44_MEGAsync_greyware_tool_keyword = /megasync\-CentOS_.{0,1000}\.x86_64\.rpm/ nocase ascii wide
                        $string45_MEGAsync_greyware_tool_keyword = /megasync\-Debian_.{0,1000}_amd64\.deb/ nocase ascii wide
                        $string46_MEGAsync_greyware_tool_keyword = /megasync\-Fedora_.{0,1000}\.x86_64\.rpm/ nocase ascii wide
                        $string47_MEGAsync_greyware_tool_keyword = /megasync\-openSUSE_Leap_.{0,1000}\.x86_64\.rpm/ nocase ascii wide
                        $string48_MEGAsync_greyware_tool_keyword = /megasync\-Raspbian_.{0,1000}_armhf\.deb/ nocase ascii wide
                        $string49_MEGAsync_greyware_tool_keyword = /MEGAsyncSetup32_.{0,1000}_RC3\.exe/ nocase ascii wide
                        $string50_MEGAsync_greyware_tool_keyword = /MEGASYNCSETUP64\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string51_MEGAsync_greyware_tool_keyword = /MEGAsyncSetup64_.{0,1000}_RC3\.exe/ nocase ascii wide
                        $string52_MEGAsync_greyware_tool_keyword = /MEGAsyncSetupArm64\.dmg/ nocase ascii wide
                        $string53_MEGAsync_greyware_tool_keyword = /megasync\-x86_64\.pkg/ nocase ascii wide
                        $string54_MEGAsync_greyware_tool_keyword = /megasync\-xUbuntu_.{0,1000}_amd64\.deb/ nocase ascii wide
                        $string55_MEGAsync_greyware_tool_keyword = "'Product'>MEGAsync</Data>" nocase ascii wide
                        $string56_MEGAsync_greyware_tool_keyword = /ReferrerUrl\=https\:\/\/mega\.io\// nocase ascii wide
                        $string57_MEGAsync_greyware_tool_keyword = "'Signature'>Mega Limited</Data>" nocase ascii wide
                        $string58_MEGAsync_greyware_tool_keyword = /Windows\\System32\\Tasks\\MEGA/ nocase ascii wide

    condition:
        any of them
}