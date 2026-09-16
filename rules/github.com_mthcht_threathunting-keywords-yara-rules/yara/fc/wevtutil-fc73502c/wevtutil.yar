rule wevtutil
{
    meta:
        description = "Detection patterns for the tool 'wevtutil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wevtutil"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /cmd.{0,1000}\swevtutil\.exe\scl\s/ nocase ascii wide
                        $string2 = /for\s\/F\s\\"tokens\=.{0,1000}\\"\s\%\%G\sin\s\(\'wevtutil\.exe\sel\'\)\sDO\s\(call\s\:do_clear\s\\"\%\%G\\"\)/ nocase ascii wide
                        $string3 = "wevtutil cl " nocase ascii wide
                        $string4 = "wevtutil clear-log" nocase ascii wide
                        $string5 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-ATAPort\// nocase ascii wide
                        $string6 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-ClassPnP\/A/ nocase ascii wide
                        $string7 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Disk\// nocase ascii wide
                        $string8 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageManagement\// nocase ascii wide
                        $string9 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-Driver\// nocase ascii wide
                        $string10 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-ManagementAgent\/WHC/ nocase ascii wide
                        $string11 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-SpaceManager\// nocase ascii wide
                        $string12 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Storport\// nocase ascii wide
                        $string13 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Tiering\/Admin/ nocase ascii wide
                        $string14 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Storage\-Tiering\-IoHeat\/Heat/ nocase ascii wide
                        $string15 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Store\/Operational/ nocase ascii wide
                        $string16 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Subsys\-Csr\/Operational/ nocase ascii wide
                        $string17 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Subsys\-SMSS\/Operational/ nocase ascii wide
                        $string18 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Superfetch\/Main/ nocase ascii wide
                        $string19 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Superfetch\/PfApLog/ nocase ascii wide
                        $string20 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Superfetch\/StoreLog/ nocase ascii wide
                        $string21 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Sysmon\/Operational/ nocase ascii wide
                        $string22 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Sysprep\/Analytic/ nocase ascii wide
                        $string23 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-System\-Profile\-HardwareId\/Diagnostic/ nocase ascii wide
                        $string24 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-SystemSettingsHandlers\/Debug/ nocase ascii wide
                        $string25 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-SystemSettingsThreshold\// nocase ascii wide
                        $string26 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TaskbarCPL\/Diagnostic/ nocase ascii wide
                        $string27 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TaskScheduler\// nocase ascii wide
                        $string28 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TCPIP\// nocase ascii wide
                        $string29 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TerminalServices\-/ nocase ascii wide
                        $string30 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Tethering\-Manager\/Analytic/ nocase ascii wide
                        $string31 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Tethering\-Station\/Analytic/ nocase ascii wide
                        $string32 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-ThemeCPL\/Diagnostic/ nocase ascii wide
                        $string33 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-ThemeUI\/Diagnostic/ nocase ascii wide
                        $string34 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Threat\-Intelligence\/Analytic/ nocase ascii wide
                        $string35 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-Time\-Service\/Operational/ nocase ascii wide
                        $string36 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TSF\-msctf\// nocase ascii wide
                        $string37 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TTS\/Diagnostic/ nocase ascii wide
                        $string38 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TunnelDriver/ nocase ascii wide
                        $string39 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TWinUI\// nocase ascii wide
                        $string40 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TZSync\// nocase ascii wide
                        $string41 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-TZUtil\/Operational/ nocase ascii wide
                        $string42 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UAC\/Operational/ nocase ascii wide
                        $string43 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UAC\-FileVirtualization\/Operational/ nocase ascii wide
                        $string44 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UIAnimation\/Diagnostic/ nocase ascii wide
                        $string45 = /wevtutil.{0,1000}\scl\s\\"Microsoft\-Windows\-UI\-Shell\/Diagnostic/ nocase ascii wide
                        $string46 = /wevtutil\.exe\scl\s/ nocase ascii wide
                        $string47 = /wevtutil\.exe\sclear\-log/ nocase ascii wide
                        $string48 = /wevtutil\.exe\ssl\s.{0,1000}\s\/e\:false/ nocase ascii wide

    condition:
        any of them
}