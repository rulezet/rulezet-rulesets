rule wevtutil
{
    meta:
        description = "Detection patterns for the tool 'wevtutil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wevtutil"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /cmd.{0,100}\swevtutil\.exe\scl\s/ nocase ascii wide
                        $string2 = /for\s\/F\s\\"tokens\=.{0,100}\\"\s\%\%G\sin\s\(\'wevtutil\.exe\sel\'\)\sDO\s\(call\s\:do_clear\s\\"\%\%G\\"\)/ nocase ascii wide
                        $string3 = "wevtutil cl " nocase ascii wide
                        $string4 = "wevtutil clear-log" nocase ascii wide
                        $string5 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Storage\-ATAPort\// nocase ascii wide
                        $string6 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Storage\-ClassPnP\/A/ nocase ascii wide
                        $string7 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Storage\-Disk\// nocase ascii wide
                        $string8 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-StorageManagement\// nocase ascii wide
                        $string9 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-Driver\// nocase ascii wide
                        $string10 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-ManagementAgent\/WHC/ nocase ascii wide
                        $string11 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-StorageSpaces\-SpaceManager\// nocase ascii wide
                        $string12 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Storage\-Storport\// nocase ascii wide
                        $string13 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Storage\-Tiering\/Admin/ nocase ascii wide
                        $string14 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Storage\-Tiering\-IoHeat\/Heat/ nocase ascii wide
                        $string15 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Store\/Operational/ nocase ascii wide
                        $string16 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Subsys\-Csr\/Operational/ nocase ascii wide
                        $string17 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Subsys\-SMSS\/Operational/ nocase ascii wide
                        $string18 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Superfetch\/Main/ nocase ascii wide
                        $string19 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Superfetch\/PfApLog/ nocase ascii wide
                        $string20 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Superfetch\/StoreLog/ nocase ascii wide
                        $string21 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Sysmon\/Operational/ nocase ascii wide
                        $string22 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Sysprep\/Analytic/ nocase ascii wide
                        $string23 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-System\-Profile\-HardwareId\/Diagnostic/ nocase ascii wide
                        $string24 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-SystemSettingsHandlers\/Debug/ nocase ascii wide
                        $string25 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-SystemSettingsThreshold\// nocase ascii wide
                        $string26 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-TaskbarCPL\/Diagnostic/ nocase ascii wide
                        $string27 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-TaskScheduler\// nocase ascii wide
                        $string28 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-TCPIP\// nocase ascii wide
                        $string29 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-TerminalServices\-/ nocase ascii wide
                        $string30 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Tethering\-Manager\/Analytic/ nocase ascii wide
                        $string31 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Tethering\-Station\/Analytic/ nocase ascii wide
                        $string32 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-ThemeCPL\/Diagnostic/ nocase ascii wide
                        $string33 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-ThemeUI\/Diagnostic/ nocase ascii wide
                        $string34 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Threat\-Intelligence\/Analytic/ nocase ascii wide
                        $string35 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-Time\-Service\/Operational/ nocase ascii wide
                        $string36 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-TSF\-msctf\// nocase ascii wide
                        $string37 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-TTS\/Diagnostic/ nocase ascii wide
                        $string38 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-TunnelDriver/ nocase ascii wide
                        $string39 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-TWinUI\// nocase ascii wide
                        $string40 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-TZSync\// nocase ascii wide
                        $string41 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-TZUtil\/Operational/ nocase ascii wide
                        $string42 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-UAC\/Operational/ nocase ascii wide
                        $string43 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-UAC\-FileVirtualization\/Operational/ nocase ascii wide
                        $string44 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-UIAnimation\/Diagnostic/ nocase ascii wide
                        $string45 = /wevtutil.{0,100}\scl\s\\"Microsoft\-Windows\-UI\-Shell\/Diagnostic/ nocase ascii wide
                        $string46 = /wevtutil\.exe\scl\s/ nocase ascii wide
                        $string47 = /wevtutil\.exe\sclear\-log/ nocase ascii wide
                        $string48 = /wevtutil\.exe\ssl\s.{0,100}\s\/e\:false/ nocase ascii wide
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