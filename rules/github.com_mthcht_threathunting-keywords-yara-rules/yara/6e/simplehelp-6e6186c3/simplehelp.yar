rule SimpleHelp
{
    meta:
        description = "Detection patterns for the tool 'SimpleHelp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimpleHelp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "\"SimpleHelp Remote Printer\"" nocase ascii wide
                        $string2 = /\/simplehelper64\.exe/ nocase ascii wide
                        $string3 = /\\JWrapper\-SimpleHelp\sRemote\sWork/ nocase ascii wide
                        $string4 = /\\JWrapper\-SimpleHelp\sTechnician/ nocase ascii wide
                        $string5 = /\\JWrapper\-SimpleHelp\sTechnician\\/ nocase ascii wide
                        $string6 = /\\Programs\\SimpleHelp\sRemote\sWork\\"/ nocase ascii wide
                        $string7 = /\\Programs\\SimpleHelp\sTechnician/ nocase ascii wide
                        $string8 = /\\remote\saccess\ssession\.exe/ nocase ascii wide
                        $string9 = /\\remote\saccess\.exe/ nocase ascii wide
                        $string10 = /\\Remote\sAccessEmbedExample\.html/ nocase ascii wide
                        $string11 = /\\Remote\sAccess\-java\-online\.jar/ nocase ascii wide
                        $string12 = /\\remote\ssupport\.exe/ nocase ascii wide
                        $string13 = /\\Remote\sSupportEmbedExample\.html/ nocase ascii wide
                        $string14 = /\\remoteaccess\-jar\-with\-dependencies\.jar/ nocase ascii wide
                        $string15 = /\\SafeBoot\\Network\\ShTemporaryService/ nocase ascii wide
                        $string16 = /\\SafeBoot\\Network\\SimpleHelp\sServer/ nocase ascii wide
                        $string17 = /\\Services\\SimpleHelp\sServer/ nocase ascii wide
                        $string18 = /\\simplegateway\.service\\"/ nocase ascii wide
                        $string19 = /\\SimpleHelp\sTechnicianEmbedExample\.html/ nocase ascii wide
                        $string20 = /\\SimpleHelp\.RemoteWork\.127_0_0_1/ nocase ascii wide
                        $string21 = /\\SimpleHelp\.Technician\.127_0_0_1/ nocase ascii wide
                        $string22 = /\\simplehelper64\.exe/ nocase ascii wide
                        $string23 = /\\simplehelp\-rw\\shell/ nocase ascii wide
                        $string24 = /\\simplehelpuninstall\.exe/ nocase ascii wide
                        $string25 = /\\SimpleService\.exe/ nocase ascii wide
                        $string26 = /\\StopSimpleGatewayService\.exe/ nocase ascii wide
                        $string27 = /\\winpty\-agent64\.exe/ nocase ascii wide
                        $string28 = ">SimpleHelp Ltd<" nocase ascii wide
                        $string29 = /bin\\Remote\sAccessLauncher\.exe/ nocase ascii wide
                        $string30 = /Elevate.{0,1000}\\elev_win\.exe/ nocase ascii wide
                        $string31 = "firewall add rule \"name=SH Remote Access Service Launcher\"" nocase ascii wide
                        $string32 = "firewall add rule \"name=SH Remote Access Service Updater\"" nocase ascii wide
                        $string33 = "firewall add rule \"name=SH Remote Access Service\"" nocase ascii wide
                        $string34 = /Manage\sRemote\sAccess\sService\.exe/ nocase ascii wide
                        $string35 = /Program\sFiles\\SimpleHelp/ nocase ascii wide
                        $string36 = /ProgramData\\JWrapper\-Remote\sAccess\\.{0,1000}\.exe/ nocase ascii wide
                        $string37 = /Remote\sAccessECompatibility\.exe/ nocase ascii wide
                        $string38 = /Remote\sAccess\-linux32arm\-offline\.tar/
                        $string39 = /Remote\sAccess\-linux32arm\-online\.tar/
                        $string40 = /Remote\sAccess\-linux32\-offline\.tar/
                        $string41 = /Remote\sAccess\-linux32\-online\.tar/
                        $string42 = /Remote\sAccess\-linux64arm\-offline\.tar/
                        $string43 = /Remote\sAccess\-linux64arm\-online\.tar/
                        $string44 = /Remote\sAccess\-linux64\-offline\.tar/
                        $string45 = /Remote\sAccess\-linux64\-online\.tar/
                        $string46 = /Remote\sAccess\-macos\-intel\-offline\.dmg/ nocase ascii wide
                        $string47 = /Remote\sAccess\-macos\-intel\-online\.dmg/ nocase ascii wide
                        $string48 = /Remote\sAccess\-macos\-offline\.dmg/ nocase ascii wide
                        $string49 = /Remote\sAccess\-macos\-online\.dmg/ nocase ascii wide
                        $string50 = /Remote\sAccess\-windows32\-offline\.exe/ nocase ascii wide
                        $string51 = /Remote\sAccess\-windows32\-online\.exe/ nocase ascii wide
                        $string52 = /Remote\sAccess\-windows64\-offline\.exe/ nocase ascii wide
                        $string53 = /remote\saccess\-windows64\-online\.exe/ nocase ascii wide
                        $string54 = /Remote\sAccess\-windows64\-online\.exe/ nocase ascii wide
                        $string55 = /Remote\sSupport\-java\-online\.jar/ nocase ascii wide
                        $string56 = /Remote\sSupport\-linux32arm\-offline\.tar/
                        $string57 = /Remote\sSupport\-linux32arm\-online\.tar/
                        $string58 = /Remote\sSupport\-linux32\-offline\.tar/
                        $string59 = /Remote\sSupport\-linux32\-online\.tar/
                        $string60 = /Remote\sSupport\-linux64arm\-offline\.tar/
                        $string61 = /Remote\sSupport\-linux64arm\-online\.tar/
                        $string62 = /Remote\sSupport\-linux64\-offline\.tar/
                        $string63 = /Remote\sSupport\-linux64\-online\.tar/
                        $string64 = /Remote\sSupport\-macos\-intel\-offline\.dmg/ nocase ascii wide
                        $string65 = /Remote\sSupport\-macos\-intel\-online\.dmg/ nocase ascii wide
                        $string66 = /Remote\sSupport\-macos\-offline\.dmg/ nocase ascii wide
                        $string67 = /Remote\sSupport\-macos\-online\.dmg/ nocase ascii wide
                        $string68 = /Remote\sSupport\-windows32\-offline\.exe/ nocase ascii wide
                        $string69 = /Remote\sSupport\-windows32\-online\.exe/ nocase ascii wide
                        $string70 = /Remote\sSupport\-windows64\-offline\.exe/ nocase ascii wide
                        $string71 = /remote\ssupport\-windows64\-online\.exe/ nocase ascii wide
                        $string72 = /Remote\sSupport\-windows64\-online\.exe/ nocase ascii wide
                        $string73 = /remote\swork\-windows64\-online\.exe/ nocase ascii wide
                        $string74 = /Remote\sWork\-windows64\-online\.exe/ nocase ascii wide
                        $string75 = /SimpleHelp\s\-\ssimple\-help\.com/ nocase ascii wide
                        $string76 = /simplehelp\sremote\swork\.exe/ nocase ascii wide
                        $string77 = /simplehelp\sremote\sworkwinlauncher\.exe/ nocase ascii wide
                        $string78 = /SimpleHelp\sRemote\sWorkWinLauncher\.exe/ nocase ascii wide
                        $string79 = /SimpleHelp\sTechnician\.exe/ nocase ascii wide
                        $string80 = /simplehelp\stechnician\.exe/ nocase ascii wide
                        $string81 = /SimpleHelp\sTechnician\-java\-online\.jar/ nocase ascii wide
                        $string82 = /SimpleHelp\sTechnician\-linux32arm\-offline\.tar/
                        $string83 = /SimpleHelp\sTechnician\-linux32arm\-online\.tar/
                        $string84 = /SimpleHelp\sTechnician\-linux32\-offline\.tar/
                        $string85 = /SimpleHelp\sTechnician\-linux32\-online\.tar/
                        $string86 = /SimpleHelp\sTechnician\-linux64arm\-offline\.tar/
                        $string87 = /SimpleHelp\sTechnician\-linux64arm\-online\.tar/
                        $string88 = /SimpleHelp\sTechnician\-linux64\-offline\.tar/
                        $string89 = /SimpleHelp\sTechnician\-linux64\-online\.tar/
                        $string90 = /SimpleHelp\sTechnician\-macos\-intel\-offline\.dmg/ nocase ascii wide
                        $string91 = /SimpleHelp\sTechnician\-macos\-intel\-online\.dmg/ nocase ascii wide
                        $string92 = /SimpleHelp\sTechnician\-macos\-offline\.dmg/ nocase ascii wide
                        $string93 = /SimpleHelp\sTechnician\-macos\-online\.dmg/ nocase ascii wide
                        $string94 = /SimpleHelp\sTechnician\-windows32\-offline\.exe/ nocase ascii wide
                        $string95 = /SimpleHelp\sTechnician\-windows32\-online\.exe/ nocase ascii wide
                        $string96 = /SimpleHelp\sTechnician\-windows64\-offline\.exe/ nocase ascii wide
                        $string97 = /simplehelp\stechnician\-windows64\-online\.exe/ nocase ascii wide
                        $string98 = /SimpleHelp\sTechnician\-windows64\-online\.exe/ nocase ascii wide
                        $string99 = /simplehelp\stechnicianwinlauncher\.exe/ nocase ascii wide
                        $string100 = /SimpleHelp\.exe/ nocase ascii wide
                        $string101 = /simplehelp\.technician\.127_0_0_1/ nocase ascii wide
                        $string102 = /SimpleHelp\-allplatforms\.zip/ nocase ascii wide
                        $string103 = /simplehelpcustomer\.exe/ nocase ascii wide
                        $string104 = /SimpleHelp\-install\-64\.exe/ nocase ascii wide

    condition:
        any of them
}