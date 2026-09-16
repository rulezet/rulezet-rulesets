rule Pyramid
{
    meta:
        description = "Detection patterns for the tool 'Pyramid' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pyramid"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-generate\s\-server\s.{0,100}\s\-setcradle\sbh\.py/ nocase ascii wide
                        $string2 = /\s\-generate\s\-setcradle\spythonmemorymodule\.py/ nocase ascii wide
                        $string3 = /\sLaZagne\.py\s/ nocase ascii wide
                        $string4 = /\spyramid\.py\s/ nocase ascii wide
                        $string5 = /\stunnel\-socks5\.py/ nocase ascii wide
                        $string6 = /\.\\\\pipe\\\\mimikatz/ nocase ascii wide
                        $string7 = /\/_distutils_hack\.zip/ nocase ascii wide
                        $string8 = /\/DonPAPI\.zip/ nocase ascii wide
                        $string9 = /\/impacket\.zip/ nocase ascii wide
                        $string10 = /\/itsdangerous\.zip/ nocase ascii wide
                        $string11 = /\/LaZagne\.py/ nocase ascii wide
                        $string12 = /\/lazagne\.zip/ nocase ascii wide
                        $string13 = /\/minidump\.zip/ nocase ascii wide
                        $string14 = /\/Pyramid\.git/ nocase ascii wide
                        $string15 = /\/pyramid\.py/ nocase ascii wide
                        $string16 = /\/pythonmemorymodule\.py/
                        $string17 = /\/tunnel\-socks5\.py/
                        $string18 = /\@WanaDecryptor\@\.exe/ nocase ascii wide
                        $string19 = /\[\+\]\sAuto\-generating\sPyramid\sconfig\sfor\smodules\sand\sagents/ nocase ascii wide
                        $string20 = /\[\+\]\sMIND\sYOUR\sOPSEC\!\sServing\sPyramid\sfiles\sfrom\sfolder\s/ nocase ascii wide
                        $string21 = /\[\+\]\sprinting\sb64encoded\(zipped\(cradle\.py\)\)\sfor\sscriptless\sexecution\son\sterminal\:/ nocase ascii wide
                        $string22 = /\[\+\]\sPyramid\sHTTP\sServer\slistening\son\sport\s/ nocase ascii wide
                        $string23 = /\\\\\.\\\\pipe\\\\blindspot\-/ nocase ascii wide
                        $string24 = /\\bin\\uactoken\.x86\.o/ nocase ascii wide
                        $string25 = /\\bin\\uactoken2\.x64\.o/ nocase ascii wide
                        $string26 = /\\bin\\wmiexec\.x64\.o/ nocase ascii wide
                        $string27 = /\\DECRYPT\-FILES\.txt/ nocase ascii wide
                        $string28 = /\\Development\\GOLD\-BACKDOOR\\/ nocase ascii wide
                        $string29 = /\\impacket\.zip/ nocase ascii wide
                        $string30 = /\\itsdangerous\.zip/ nocase ascii wide
                        $string31 = /\\LaZagne\.py/ nocase ascii wide
                        $string32 = /\\lazagne\.zip/ nocase ascii wide
                        $string33 = /\\netview\.x64\.dll/ nocase ascii wide
                        $string34 = /\\pxlib\\bin\\wmiexec\.x86\.o/ nocase ascii wide
                        $string35 = /\\pyramid\.py/ nocase ascii wide
                        $string36 = /\\tunnel\-socks5\.py/ nocase ascii wide
                        $string37 = /\\users\\public\\desktop\\Fix\-Your\-Files\.txt/ nocase ascii wide
                        $string38 = "6f83bb55a9762c656e90c49fd505ba79414edf22a89a4029f96a6ff784716e29" nocase ascii wide
                        $string39 = "816bac589fcdd14efd90df8fecfadd0b1908dcd18a3617ef9f64170fee14ad5c" nocase ascii wide
                        $string40 = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" nocase ascii wide
                        $string41 = /bin\\psexec_command\.x64\.o/ nocase ascii wide
                        $string42 = "c518104a683209a63029169a1a69e839cf0a7baf26f29bf1fcc96e6c4f776245" nocase ascii wide
                        $string43 = "ddacbf2fc85fd85cdbe8016b19f2f783acb17dbaf6361e9827039885d382e8d2" nocase ascii wide
                        $string44 = /hashdump\.x64\.dll/ nocase ascii wide
                        $string45 = /HOW_TO_DECYPHER_FILES\.txt/ nocase ascii wide
                        $string46 = /KeePassHax\.dll/ nocase ascii wide
                        $string47 = /keylogger\.dll/ nocase ascii wide
                        $string48 = /keylogger\.x64\.dll/ nocase ascii wide
                        $string49 = /ldapdomaindump\.zip/ nocase ascii wide
                        $string50 = /mimikatz\.log/ nocase ascii wide
                        $string51 = /minikerberos\.zip/ nocase ascii wide
                        $string52 = "naksyn/Pyramid" nocase ascii wide
                        $string53 = /pxlib\\bin\\kerberos\.x64\.o/ nocase ascii wide
                        $string54 = /pypykatz\.zip/ nocase ascii wide
                        $string55 = /Pyramid\-main\.zip/ nocase ascii wide
                        $string56 = /Release\-ReflectiveDLL\\Implant\.x64\.pdb/ nocase ascii wide
                        $string57 = /secretsdump\.py/ nocase ascii wide
                        $string58 = /Serve\sPyramid\sfiles\sover\sHTTP\/S\sand\sprovide\sbasic\sauthentication\./ nocase ascii wide
                        $string59 = /timestomp\.x64\.o/ nocase ascii wide
                        $string60 = "User-Agent: pproxy-" nocase ascii wide
                        $string61 = /webinject64\.dll/ nocase ascii wide
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