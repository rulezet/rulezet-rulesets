rule rule_wevtutil_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wevtutil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wevtutil"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_wevtutil_greyware_tool_keyword = /cmd.{0,1000}\swevtutil\.exe\scl\s/ nocase ascii wide
                        $string2_wevtutil_greyware_tool_keyword = /for\s\/F\s\\"tokens\=.{0,1000}\\"\s\%\%G\sin\s\(\'wevtutil\.exe\sel\'\)\sDO\s\(call\s\:do_clear\s\\"\%\%G\\"\)/ nocase ascii wide
                        $string3_wevtutil_greyware_tool_keyword = "wevtutil cl " nocase ascii wide
                        $string4_wevtutil_greyware_tool_keyword = "wevtutil clear-log" nocase ascii wide
                        $string5_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-ATAPort\// nocase ascii wide
                        $string6_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-ClassPnP\/A/ nocase ascii wide
                        $string7_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Disk\// nocase ascii wide
                        $string8_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageManagement\// nocase ascii wide
                        $string9_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-Driver\// nocase ascii wide
                        $string10_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-ManagementAgent\/WHC/ nocase ascii wide
                        $string11_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-SpaceManager\// nocase ascii wide
                        $string12_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Storport\// nocase ascii wide
                        $string13_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Tiering\/Admin/ nocase ascii wide
                        $string14_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Tiering\-IoHeat\/Heat/ nocase ascii wide
                        $string15_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Store\/Operational/ nocase ascii wide
                        $string16_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Subsys\-Csr\/Operational/ nocase ascii wide
                        $string17_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Subsys\-SMSS\/Operational/ nocase ascii wide
                        $string18_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Superfetch\/Main/ nocase ascii wide
                        $string19_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Superfetch\/PfApLog/ nocase ascii wide
                        $string20_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Superfetch\/StoreLog/ nocase ascii wide
                        $string21_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Sysmon\/Operational/ nocase ascii wide
                        $string22_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Sysprep\/Analytic/ nocase ascii wide
                        $string23_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-System\-Profile\-HardwareId\/Diagnostic/ nocase ascii wide
                        $string24_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-SystemSettingsHandlers\/Debug/ nocase ascii wide
                        $string25_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-SystemSettingsThreshold\// nocase ascii wide
                        $string26_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TaskbarCPL\/Diagnostic/ nocase ascii wide
                        $string27_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TaskScheduler\// nocase ascii wide
                        $string28_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TCPIP\// nocase ascii wide
                        $string29_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TerminalServices\-/ nocase ascii wide
                        $string30_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Tethering\-Manager\/Analytic/ nocase ascii wide
                        $string31_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Tethering\-Station\/Analytic/ nocase ascii wide
                        $string32_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-ThemeCPL\/Diagnostic/ nocase ascii wide
                        $string33_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-ThemeUI\/Diagnostic/ nocase ascii wide
                        $string34_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Threat\-Intelligence\/Analytic/ nocase ascii wide
                        $string35_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Time\-Service\/Operational/ nocase ascii wide
                        $string36_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TSF\-msctf\// nocase ascii wide
                        $string37_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TTS\/Diagnostic/ nocase ascii wide
                        $string38_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TunnelDriver/ nocase ascii wide
                        $string39_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TWinUI\// nocase ascii wide
                        $string40_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TZSync\// nocase ascii wide
                        $string41_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TZUtil\/Operational/ nocase ascii wide
                        $string42_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UAC\/Operational/ nocase ascii wide
                        $string43_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UAC\-FileVirtualization\/Operational/ nocase ascii wide
                        $string44_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UIAnimation\/Diagnostic/ nocase ascii wide
                        $string45_wevtutil_greyware_tool_keyword = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UI\-Shell\/Diagnostic/ nocase ascii wide
                        $string46_wevtutil_greyware_tool_keyword = /wevtutil\.exe\scl\s/ nocase ascii wide
                        $string47_wevtutil_greyware_tool_keyword = /wevtutil\.exe\sclear\-log/ nocase ascii wide
                        $string48_wevtutil_greyware_tool_keyword = /wevtutil\.exe\ssl\s.{0,1000}\s\/e\:false/ nocase ascii wide

    condition:
        any of them
}