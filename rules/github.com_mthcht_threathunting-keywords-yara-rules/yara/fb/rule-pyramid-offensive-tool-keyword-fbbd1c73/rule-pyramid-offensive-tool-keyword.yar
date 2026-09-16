rule rule_Pyramid_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Pyramid' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pyramid"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Pyramid_offensive_tool_keyword = /\s\-generate\s\-server\s.{0,1000}\s\-setcradle\sbh\.py/ nocase ascii wide
                        $string2_Pyramid_offensive_tool_keyword = /\s\-generate\s\-setcradle\spythonmemorymodule\.py/ nocase ascii wide
                        $string3_Pyramid_offensive_tool_keyword = /\sLaZagne\.py\s/ nocase ascii wide
                        $string4_Pyramid_offensive_tool_keyword = /\spyramid\.py\s/ nocase ascii wide
                        $string5_Pyramid_offensive_tool_keyword = /\stunnel\-socks5\.py/ nocase ascii wide
                        $string6_Pyramid_offensive_tool_keyword = /\.\\\\pipe\\\\mimikatz/ nocase ascii wide
                        $string7_Pyramid_offensive_tool_keyword = /\/_distutils_hack\.zip/ nocase ascii wide
                        $string8_Pyramid_offensive_tool_keyword = /\/DonPAPI\.zip/ nocase ascii wide
                        $string9_Pyramid_offensive_tool_keyword = /\/impacket\.zip/ nocase ascii wide
                        $string10_Pyramid_offensive_tool_keyword = /\/itsdangerous\.zip/ nocase ascii wide
                        $string11_Pyramid_offensive_tool_keyword = /\/LaZagne\.py/ nocase ascii wide
                        $string12_Pyramid_offensive_tool_keyword = /\/lazagne\.zip/ nocase ascii wide
                        $string13_Pyramid_offensive_tool_keyword = /\/minidump\.zip/ nocase ascii wide
                        $string14_Pyramid_offensive_tool_keyword = /\/Pyramid\.git/ nocase ascii wide
                        $string15_Pyramid_offensive_tool_keyword = /\/pyramid\.py/ nocase ascii wide
                        $string16_Pyramid_offensive_tool_keyword = /\/pythonmemorymodule\.py/
                        $string17_Pyramid_offensive_tool_keyword = /\/tunnel\-socks5\.py/
                        $string18_Pyramid_offensive_tool_keyword = /\@WanaDecryptor\@\.exe/ nocase ascii wide
                        $string19_Pyramid_offensive_tool_keyword = /\[\+\]\sAuto\-generating\sPyramid\sconfig\sfor\smodules\sand\sagents/ nocase ascii wide
                        $string20_Pyramid_offensive_tool_keyword = /\[\+\]\sMIND\sYOUR\sOPSEC\!\sServing\sPyramid\sfiles\sfrom\sfolder\s/ nocase ascii wide
                        $string21_Pyramid_offensive_tool_keyword = /\[\+\]\sprinting\sb64encoded\(zipped\(cradle\.py\)\)\sfor\sscriptless\sexecution\son\sterminal\:/ nocase ascii wide
                        $string22_Pyramid_offensive_tool_keyword = /\[\+\]\sPyramid\sHTTP\sServer\slistening\son\sport\s/ nocase ascii wide
                        $string23_Pyramid_offensive_tool_keyword = /\\\\\.\\\\pipe\\\\blindspot\-/ nocase ascii wide
                        $string24_Pyramid_offensive_tool_keyword = /\\bin\\uactoken\.x86\.o/ nocase ascii wide
                        $string25_Pyramid_offensive_tool_keyword = /\\bin\\uactoken2\.x64\.o/ nocase ascii wide
                        $string26_Pyramid_offensive_tool_keyword = /\\bin\\wmiexec\.x64\.o/ nocase ascii wide
                        $string27_Pyramid_offensive_tool_keyword = /\\DECRYPT\-FILES\.txt/ nocase ascii wide
                        $string28_Pyramid_offensive_tool_keyword = /\\Development\\GOLD\-BACKDOOR\\/ nocase ascii wide
                        $string29_Pyramid_offensive_tool_keyword = /\\impacket\.zip/ nocase ascii wide
                        $string30_Pyramid_offensive_tool_keyword = /\\itsdangerous\.zip/ nocase ascii wide
                        $string31_Pyramid_offensive_tool_keyword = /\\LaZagne\.py/ nocase ascii wide
                        $string32_Pyramid_offensive_tool_keyword = /\\lazagne\.zip/ nocase ascii wide
                        $string33_Pyramid_offensive_tool_keyword = /\\netview\.x64\.dll/ nocase ascii wide
                        $string34_Pyramid_offensive_tool_keyword = /\\pxlib\\bin\\wmiexec\.x86\.o/ nocase ascii wide
                        $string35_Pyramid_offensive_tool_keyword = /\\pyramid\.py/ nocase ascii wide
                        $string36_Pyramid_offensive_tool_keyword = /\\tunnel\-socks5\.py/ nocase ascii wide
                        $string37_Pyramid_offensive_tool_keyword = /\\users\\public\\desktop\\Fix\-Your\-Files\.txt/ nocase ascii wide
                        $string38_Pyramid_offensive_tool_keyword = "6f83bb55a9762c656e90c49fd505ba79414edf22a89a4029f96a6ff784716e29" nocase ascii wide
                        $string39_Pyramid_offensive_tool_keyword = "816bac589fcdd14efd90df8fecfadd0b1908dcd18a3617ef9f64170fee14ad5c" nocase ascii wide
                        $string40_Pyramid_offensive_tool_keyword = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" nocase ascii wide
                        $string41_Pyramid_offensive_tool_keyword = /bin\\psexec_command\.x64\.o/ nocase ascii wide
                        $string42_Pyramid_offensive_tool_keyword = "c518104a683209a63029169a1a69e839cf0a7baf26f29bf1fcc96e6c4f776245" nocase ascii wide
                        $string43_Pyramid_offensive_tool_keyword = "ddacbf2fc85fd85cdbe8016b19f2f783acb17dbaf6361e9827039885d382e8d2" nocase ascii wide
                        $string44_Pyramid_offensive_tool_keyword = /hashdump\.x64\.dll/ nocase ascii wide
                        $string45_Pyramid_offensive_tool_keyword = /HOW_TO_DECYPHER_FILES\.txt/ nocase ascii wide
                        $string46_Pyramid_offensive_tool_keyword = /KeePassHax\.dll/ nocase ascii wide
                        $string47_Pyramid_offensive_tool_keyword = /keylogger\.dll/ nocase ascii wide
                        $string48_Pyramid_offensive_tool_keyword = /keylogger\.x64\.dll/ nocase ascii wide
                        $string49_Pyramid_offensive_tool_keyword = /ldapdomaindump\.zip/ nocase ascii wide
                        $string50_Pyramid_offensive_tool_keyword = /mimikatz\.log/ nocase ascii wide
                        $string51_Pyramid_offensive_tool_keyword = /minikerberos\.zip/ nocase ascii wide
                        $string52_Pyramid_offensive_tool_keyword = "naksyn/Pyramid" nocase ascii wide
                        $string53_Pyramid_offensive_tool_keyword = /pxlib\\bin\\kerberos\.x64\.o/ nocase ascii wide
                        $string54_Pyramid_offensive_tool_keyword = /pypykatz\.zip/ nocase ascii wide
                        $string55_Pyramid_offensive_tool_keyword = /Pyramid\-main\.zip/ nocase ascii wide
                        $string56_Pyramid_offensive_tool_keyword = /Release\-ReflectiveDLL\\Implant\.x64\.pdb/ nocase ascii wide
                        $string57_Pyramid_offensive_tool_keyword = /secretsdump\.py/ nocase ascii wide
                        $string58_Pyramid_offensive_tool_keyword = /Serve\sPyramid\sfiles\sover\sHTTP\/S\sand\sprovide\sbasic\sauthentication\./ nocase ascii wide
                        $string59_Pyramid_offensive_tool_keyword = /timestomp\.x64\.o/ nocase ascii wide
                        $string60_Pyramid_offensive_tool_keyword = "User-Agent: pproxy-" nocase ascii wide
                        $string61_Pyramid_offensive_tool_keyword = /webinject64\.dll/ nocase ascii wide

    condition:
        any of them
}