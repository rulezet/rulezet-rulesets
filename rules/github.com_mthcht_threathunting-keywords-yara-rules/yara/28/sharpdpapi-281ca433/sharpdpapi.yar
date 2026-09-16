rule SharpDPAPI
{
    meta:
        description = "Detection patterns for the tool 'SharpDPAPI' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDPAPI"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbackupkey.{0,1000}\s\/server\:.{0,1000}\s\/file.{0,1000}\.pvk/ nocase ascii wide
                        $string2 = /\sblob\s\/target\:.{0,1000}\.bin.{0,1000}\s\/pvk\:/ nocase ascii wide
                        $string3 = /\sblob\s\/target\:.{0,1000}\.bin.{0,1000}\s\/unprotect/ nocase ascii wide
                        $string4 = " credentials /pvk:" nocase ascii wide
                        $string5 = " keepass /unprotect" nocase ascii wide
                        $string6 = /\sps\s\/target\:.{0,1000}\.xml\s\/unprotect/ nocase ascii wide
                        $string7 = /\svaults\s\/target\:.{0,1000}\s\/pvk\:/ nocase ascii wide
                        $string8 = /\.exe\s\scertificates\s\/pvk\:.{0,1000}\.pvk/ nocase ascii wide
                        $string9 = /\.exe\s\skeepass\s\/unprotect/ nocase ascii wide
                        $string10 = /\.exe\sbackupkey\s\/nowrap\s.{0,1000}\.pvk/ nocase ascii wide
                        $string11 = /\.exe\sbackupkey\s\/server\:/ nocase ascii wide
                        $string12 = /\.exe\sblob\s\/target\:C\:\\Temp\\/ nocase ascii wide
                        $string13 = /\.exe\scertificates\s\/mkfile\:.{0,1000}\.txt/ nocase ascii wide
                        $string14 = /\.exe\scertificates\s\/unprotect/ nocase ascii wide
                        $string15 = /\.exe\scredentials\s\/pvk\:.{0,1000}\.pvk/ nocase ascii wide
                        $string16 = /\.exe\smachinemasterkeys/ nocase ascii wide
                        $string17 = /\.exe\smachinetriage/ nocase ascii wide
                        $string18 = /\.exe\smachinevaults/ nocase ascii wide
                        $string19 = /\.exe\smasterkeys\s\/hashes/ nocase ascii wide
                        $string20 = /\.exe\smasterkeys\s\/hashes/ nocase ascii wide
                        $string21 = /\.exe\smasterkeys\s\/pvk\:/ nocase ascii wide
                        $string22 = /\.exe\sps\s\/target\:C\:\\Temp\\.{0,1000}\s\/unprotect/ nocase ascii wide
                        $string23 = /\.exe\srdg\s\/unprotect/ nocase ascii wide
                        $string24 = /\.exe\striage\s\/password\:/ nocase ascii wide
                        $string25 = /\/SharpDPAPI\.exe/ nocase ascii wide
                        $string26 = /\/SharpDPAPI\.git/ nocase ascii wide
                        $string27 = /\[SharpDPAPI\.Program\]\:\:Main\(\\"machinemasterkeys\\"\)/ nocase ascii wide
                        $string28 = /\[X\]\sMust\sbe\selevated\sto\striage\sSYSTEM\scredentials\!/ nocase ascii wide
                        $string29 = /\[X\]\sMust\sbe\selevated\sto\striage\sSYSTEM\smasterkeys\!/ nocase ascii wide
                        $string30 = /\[X\]\sMust\sbe\selevated\sto\striage\sSYSTEM\svaults\!/ nocase ascii wide
                        $string31 = /\\Commands\\Machinecredentials\.cs/ nocase ascii wide
                        $string32 = /\\SharpDPAPI\.exe/ nocase ascii wide
                        $string33 = /\\SharpDPAPI\\/ nocase ascii wide
                        $string34 = /\]\sWill\sdecrypt\suser\smasterkeys\swith\sNTLM\shash\:\s/ nocase ascii wide
                        $string35 = ">SharpDPAPI<" nocase ascii wide
                        $string36 = "2F00A05B-263D-4FCC-846B-DA82BD684603" nocase ascii wide
                        $string37 = "5d975e81c68574849bb0fec4c6d2116a4ba7dd58bdd1710463ab75d9a8054bc3" nocase ascii wide
                        $string38 = "5F026C27-F8E6-4052-B231-8451C6A73838" nocase ascii wide
                        $string39 = "d907d7686b725441db1deb645a7079ca79f4dd1d8a18ca4b2bb98c12622603ef" nocase ascii wide
                        $string40 = "GhostPack/SharpDPAPI" nocase ascii wide
                        $string41 = /MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
                        $string42 = /SharpChrome.{0,1000}\sbackupkey\s.{0,1000}\.pvk/ nocase ascii wide
                        $string43 = "SharpDPAPI backupkey" nocase ascii wide
                        $string44 = "SharpDPAPI backupkey" nocase ascii wide
                        $string45 = "SharpDPAPI completed in " nocase ascii wide
                        $string46 = /SharpDPAPI.{0,1000}\scredentias\s/ nocase ascii wide
                        $string47 = /SharpDPAPI.{0,1000}\svaults\s/ nocase ascii wide
                        $string48 = /SharpDPAPI\.csproj/ nocase ascii wide
                        $string49 = /SharpDPAPI\.Domain/ nocase ascii wide
                        $string50 = /SharpDPAPI\.exe/ nocase ascii wide
                        $string51 = /SharpDPAPI\.Helpers\./ nocase ascii wide
                        $string52 = /SharpDPAPI\.ps1/ nocase ascii wide
                        $string53 = /SharpDPAPI\.sln/ nocase ascii wide
                        $string54 = /SharpDPAPI\.txt/ nocase ascii wide
                        $string55 = "SharpDPAPI-master" nocase ascii wide

    condition:
        any of them
}