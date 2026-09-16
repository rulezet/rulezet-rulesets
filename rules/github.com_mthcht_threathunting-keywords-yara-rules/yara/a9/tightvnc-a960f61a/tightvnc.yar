rule tightvnc
{
    meta:
        description = "Detection patterns for the tool 'tightvnc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tightvnc"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " -service TightVNC Server" nocase ascii wide
                        $string2 = /\.\\TightVNC1/ nocase ascii wide
                        $string3 = /\.\\TightVNC2/ nocase ascii wide
                        $string4 = /\.\\TightVNC3/ nocase ascii wide
                        $string5 = /\/tightvnc\-.{0,100}\.msi/ nocase ascii wide
                        $string6 = /\\mlnhcpkomdeavomsjalt/ nocase ascii wide
                        $string7 = /\\Programs\\TightVNC/ nocase ascii wide
                        $string8 = /\\SOFTWARE\\WOW6432Node\\TightVNC\\/ nocase ascii wide
                        $string9 = /\\TightVNC\sServer/ nocase ascii wide
                        $string10 = /\\tightvnc\-/ nocase ascii wide
                        $string11 = /\\TightVNC_Service_Control/ nocase ascii wide
                        $string12 = /\\TVN_log_pipe_public_name/ nocase ascii wide
                        $string13 = ">TightVNC Viewer<" nocase ascii wide
                        $string14 = /00\:\\\.vnc\\/ nocase ascii wide
                        $string15 = /GlavSoft\sLLC\./ nocase ascii wide
                        $string16 = /HKCR\\\.vnc/ nocase ascii wide
                        $string17 = /program\sfiles\s\(x86\)\\tightvnc\\/ nocase ascii wide
                        $string18 = /ProgramData\\TightVNC/ nocase ascii wide
                        $string19 = "TightVNC Service" nocase ascii wide
                        $string20 = /TightVNC\sWeb\sSite\.url/ nocase ascii wide
                        $string21 = "tvnserver" nocase ascii wide
                        $string22 = /tvnserver\.exe/ nocase ascii wide
                        $string23 = /tvnviewer\.exe/ nocase ascii wide
                        $string24 = /VncViewer\.Config/ nocase ascii wide
                        $string25 = /www\.tightvnc\.com\/download\/.{0,100}\=/ nocase ascii wide
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