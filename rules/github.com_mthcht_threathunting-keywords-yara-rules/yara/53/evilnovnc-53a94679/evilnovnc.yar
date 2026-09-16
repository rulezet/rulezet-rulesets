rule EvilnoVNC
{
    meta:
        description = "Detection patterns for the tool 'EvilnoVNC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilnoVNC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " EvilnoVNC by @JoelGMSec"
                        $string2 = " EvilnoVNC" nocase ascii wide
                        $string3 = " --vnc localhost:5900 --listen 5980"
                        $string4 = /\/bin\/bash\s\-c\s\\"php\s\-q\s\-S\s0\.0\.0\.0\:80\s\&\\"\s\>\s\/dev\/null\s2\>\&1/
                        $string5 = /\/Downloads\/Keylogger\.txt/
                        $string6 = /\/Downloads\/keypress\.log/
                        $string7 = /\/EvilnoVNC\.git/ nocase ascii wide
                        $string8 = /\/noVNC\/index\.html/
                        $string9 = "/noVNC/utils/novnc_proxy"
                        $string10 = /\/noVNC\/vnc_lite\.html/
                        $string11 = /\/start\.sh\sdynamic\s/
                        $string12 = /\/startVNC\.sh/
                        $string13 = /\/tmp\/resolution\.txt.{0,100}server\.sh/
                        $string14 = "/utils/novnc_proxy"
                        $string15 = /\\EvilnoVNC/ nocase ascii wide
                        $string16 = /\\Keylogger\.txt/ nocase ascii wide
                        $string17 = "1a571ac5b806ffce2605b57753f74653ddb392e5afdb0e49c3e9e8d76e561568" nocase ascii wide
                        $string18 = "D0:B6:9D:86:6D:AE:B4:E1:CA:F0:C1:F5:4D:82:45:7E:13:06:CD:1A:DE:49:A3:80:DC:21:6A:5C:A8:F4:84:1B"
                        $string19 = "docker rmi evilnginx" nocase ascii wide
                        $string20 = "docker rmi evilnovnc" nocase ascii wide
                        $string21 = /echo\s\'user\sALL\=\(ALL\)\sNOPASSWD\:ALL\'\s\>\>\s\/etc\/sudoers/
                        $string22 = /EvilnoVNC\s\(\)\s/
                        $string23 = "EvilnoVNC by @JoelGMSec" nocase ascii wide
                        $string24 = "EvilnoVNC Server" nocase ascii wide
                        $string25 = /evilnovnc\.Dockerfile/ nocase ascii wide
                        $string26 = /EvilnoVNC\/run\.sh/
                        $string27 = "EvilnoVNC/tmp/"
                        $string28 = "EvilnoVNC-main" nocase ascii wide
                        $string29 = /Import\sstealed\ssession\sto\sChromium\.\./ nocase ascii wide
                        $string30 = /JoelGMSec\s\-\shttps\:\/\/darkbyte\.net/
                        $string31 = "JoelGMSec/EvilnoVNC" nocase ascii wide
                        $string32 = /keylogger\.py/ nocase ascii wide
                        $string33 = /kiosk\.sh.{0,100}startVNC\.sh/
                        $string34 = "nandydark/Linux-keylogger"
                        $string35 = "novnc_proxy --vnc localhost:"
                        $string36 = /php\s\-q\s\-S\s0\.0\.0\.0\:8111/
                        $string37 = "Wanetty inspired by @JoelGMSec"
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