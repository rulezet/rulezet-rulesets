rule rule_SimpleHelp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SimpleHelp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimpleHelp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_SimpleHelp_greyware_tool_keyword = "\"SimpleHelp Remote Printer\"" nocase ascii wide
                        $string2_SimpleHelp_greyware_tool_keyword = /\/simplehelper64\.exe/ nocase ascii wide
                        $string3_SimpleHelp_greyware_tool_keyword = /\\JWrapper\-SimpleHelp\sRemote\sWork/ nocase ascii wide
                        $string4_SimpleHelp_greyware_tool_keyword = /\\JWrapper\-SimpleHelp\sTechnician/ nocase ascii wide
                        $string5_SimpleHelp_greyware_tool_keyword = /\\JWrapper\-SimpleHelp\sTechnician\\/ nocase ascii wide
                        $string6_SimpleHelp_greyware_tool_keyword = /\\Programs\\SimpleHelp\sRemote\sWork\\"/ nocase ascii wide
                        $string7_SimpleHelp_greyware_tool_keyword = /\\Programs\\SimpleHelp\sTechnician/ nocase ascii wide
                        $string8_SimpleHelp_greyware_tool_keyword = /\\remote\saccess\ssession\.exe/ nocase ascii wide
                        $string9_SimpleHelp_greyware_tool_keyword = /\\remote\saccess\.exe/ nocase ascii wide
                        $string10_SimpleHelp_greyware_tool_keyword = /\\Remote\sAccessEmbedExample\.html/ nocase ascii wide
                        $string11_SimpleHelp_greyware_tool_keyword = /\\Remote\sAccess\-java\-online\.jar/ nocase ascii wide
                        $string12_SimpleHelp_greyware_tool_keyword = /\\remote\ssupport\.exe/ nocase ascii wide
                        $string13_SimpleHelp_greyware_tool_keyword = /\\Remote\sSupportEmbedExample\.html/ nocase ascii wide
                        $string14_SimpleHelp_greyware_tool_keyword = /\\remoteaccess\-jar\-with\-dependencies\.jar/ nocase ascii wide
                        $string15_SimpleHelp_greyware_tool_keyword = /\\SafeBoot\\Network\\ShTemporaryService/ nocase ascii wide
                        $string16_SimpleHelp_greyware_tool_keyword = /\\SafeBoot\\Network\\SimpleHelp\sServer/ nocase ascii wide
                        $string17_SimpleHelp_greyware_tool_keyword = /\\Services\\SimpleHelp\sServer/ nocase ascii wide
                        $string18_SimpleHelp_greyware_tool_keyword = /\\simplegateway\.service\\"/ nocase ascii wide
                        $string19_SimpleHelp_greyware_tool_keyword = /\\SimpleHelp\sTechnicianEmbedExample\.html/ nocase ascii wide
                        $string20_SimpleHelp_greyware_tool_keyword = /\\SimpleHelp\.RemoteWork\.127_0_0_1/ nocase ascii wide
                        $string21_SimpleHelp_greyware_tool_keyword = /\\SimpleHelp\.Technician\.127_0_0_1/ nocase ascii wide
                        $string22_SimpleHelp_greyware_tool_keyword = /\\simplehelper64\.exe/ nocase ascii wide
                        $string23_SimpleHelp_greyware_tool_keyword = /\\simplehelp\-rw\\shell/ nocase ascii wide
                        $string24_SimpleHelp_greyware_tool_keyword = /\\simplehelpuninstall\.exe/ nocase ascii wide
                        $string25_SimpleHelp_greyware_tool_keyword = /\\SimpleService\.exe/ nocase ascii wide
                        $string26_SimpleHelp_greyware_tool_keyword = /\\StopSimpleGatewayService\.exe/ nocase ascii wide
                        $string27_SimpleHelp_greyware_tool_keyword = /\\winpty\-agent64\.exe/ nocase ascii wide
                        $string28_SimpleHelp_greyware_tool_keyword = ">SimpleHelp Ltd<" nocase ascii wide
                        $string29_SimpleHelp_greyware_tool_keyword = /bin\\Remote\sAccessLauncher\.exe/ nocase ascii wide
                        $string30_SimpleHelp_greyware_tool_keyword = /Elevate.{0,100}\\elev_win\.exe/ nocase ascii wide
                        $string31_SimpleHelp_greyware_tool_keyword = "firewall add rule \"name=SH Remote Access Service Launcher\"" nocase ascii wide
                        $string32_SimpleHelp_greyware_tool_keyword = "firewall add rule \"name=SH Remote Access Service Updater\"" nocase ascii wide
                        $string33_SimpleHelp_greyware_tool_keyword = "firewall add rule \"name=SH Remote Access Service\"" nocase ascii wide
                        $string34_SimpleHelp_greyware_tool_keyword = /Manage\sRemote\sAccess\sService\.exe/ nocase ascii wide
                        $string35_SimpleHelp_greyware_tool_keyword = /Program\sFiles\\SimpleHelp/ nocase ascii wide
                        $string36_SimpleHelp_greyware_tool_keyword = /ProgramData\\JWrapper\-Remote\sAccess\\.{0,100}\.exe/ nocase ascii wide
                        $string37_SimpleHelp_greyware_tool_keyword = /Remote\sAccessECompatibility\.exe/ nocase ascii wide
                        $string38_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-linux32arm\-offline\.tar/
                        $string39_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-linux32arm\-online\.tar/
                        $string40_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-linux32\-offline\.tar/
                        $string41_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-linux32\-online\.tar/
                        $string42_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-linux64arm\-offline\.tar/
                        $string43_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-linux64arm\-online\.tar/
                        $string44_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-linux64\-offline\.tar/
                        $string45_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-linux64\-online\.tar/
                        $string46_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-macos\-intel\-offline\.dmg/ nocase ascii wide
                        $string47_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-macos\-intel\-online\.dmg/ nocase ascii wide
                        $string48_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-macos\-offline\.dmg/ nocase ascii wide
                        $string49_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-macos\-online\.dmg/ nocase ascii wide
                        $string50_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-windows32\-offline\.exe/ nocase ascii wide
                        $string51_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-windows32\-online\.exe/ nocase ascii wide
                        $string52_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-windows64\-offline\.exe/ nocase ascii wide
                        $string53_SimpleHelp_greyware_tool_keyword = /remote\saccess\-windows64\-online\.exe/ nocase ascii wide
                        $string54_SimpleHelp_greyware_tool_keyword = /Remote\sAccess\-windows64\-online\.exe/ nocase ascii wide
                        $string55_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-java\-online\.jar/ nocase ascii wide
                        $string56_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-linux32arm\-offline\.tar/
                        $string57_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-linux32arm\-online\.tar/
                        $string58_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-linux32\-offline\.tar/
                        $string59_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-linux32\-online\.tar/
                        $string60_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-linux64arm\-offline\.tar/
                        $string61_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-linux64arm\-online\.tar/
                        $string62_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-linux64\-offline\.tar/
                        $string63_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-linux64\-online\.tar/
                        $string64_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-macos\-intel\-offline\.dmg/ nocase ascii wide
                        $string65_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-macos\-intel\-online\.dmg/ nocase ascii wide
                        $string66_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-macos\-offline\.dmg/ nocase ascii wide
                        $string67_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-macos\-online\.dmg/ nocase ascii wide
                        $string68_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-windows32\-offline\.exe/ nocase ascii wide
                        $string69_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-windows32\-online\.exe/ nocase ascii wide
                        $string70_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-windows64\-offline\.exe/ nocase ascii wide
                        $string71_SimpleHelp_greyware_tool_keyword = /remote\ssupport\-windows64\-online\.exe/ nocase ascii wide
                        $string72_SimpleHelp_greyware_tool_keyword = /Remote\sSupport\-windows64\-online\.exe/ nocase ascii wide
                        $string73_SimpleHelp_greyware_tool_keyword = /remote\swork\-windows64\-online\.exe/ nocase ascii wide
                        $string74_SimpleHelp_greyware_tool_keyword = /Remote\sWork\-windows64\-online\.exe/ nocase ascii wide
                        $string75_SimpleHelp_greyware_tool_keyword = /SimpleHelp\s\-\ssimple\-help\.com/ nocase ascii wide
                        $string76_SimpleHelp_greyware_tool_keyword = /simplehelp\sremote\swork\.exe/ nocase ascii wide
                        $string77_SimpleHelp_greyware_tool_keyword = /simplehelp\sremote\sworkwinlauncher\.exe/ nocase ascii wide
                        $string78_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sRemote\sWorkWinLauncher\.exe/ nocase ascii wide
                        $string79_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\.exe/ nocase ascii wide
                        $string80_SimpleHelp_greyware_tool_keyword = /simplehelp\stechnician\.exe/ nocase ascii wide
                        $string81_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-java\-online\.jar/ nocase ascii wide
                        $string82_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-linux32arm\-offline\.tar/
                        $string83_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-linux32arm\-online\.tar/
                        $string84_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-linux32\-offline\.tar/
                        $string85_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-linux32\-online\.tar/
                        $string86_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-linux64arm\-offline\.tar/
                        $string87_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-linux64arm\-online\.tar/
                        $string88_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-linux64\-offline\.tar/
                        $string89_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-linux64\-online\.tar/
                        $string90_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-macos\-intel\-offline\.dmg/ nocase ascii wide
                        $string91_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-macos\-intel\-online\.dmg/ nocase ascii wide
                        $string92_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-macos\-offline\.dmg/ nocase ascii wide
                        $string93_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-macos\-online\.dmg/ nocase ascii wide
                        $string94_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-windows32\-offline\.exe/ nocase ascii wide
                        $string95_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-windows32\-online\.exe/ nocase ascii wide
                        $string96_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-windows64\-offline\.exe/ nocase ascii wide
                        $string97_SimpleHelp_greyware_tool_keyword = /simplehelp\stechnician\-windows64\-online\.exe/ nocase ascii wide
                        $string98_SimpleHelp_greyware_tool_keyword = /SimpleHelp\sTechnician\-windows64\-online\.exe/ nocase ascii wide
                        $string99_SimpleHelp_greyware_tool_keyword = /simplehelp\stechnicianwinlauncher\.exe/ nocase ascii wide
                        $string100_SimpleHelp_greyware_tool_keyword = /SimpleHelp\.exe/ nocase ascii wide
                        $string101_SimpleHelp_greyware_tool_keyword = /simplehelp\.technician\.127_0_0_1/ nocase ascii wide
                        $string102_SimpleHelp_greyware_tool_keyword = /SimpleHelp\-allplatforms\.zip/ nocase ascii wide
                        $string103_SimpleHelp_greyware_tool_keyword = /simplehelpcustomer\.exe/ nocase ascii wide
                        $string104_SimpleHelp_greyware_tool_keyword = /SimpleHelp\-install\-64\.exe/ nocase ascii wide
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