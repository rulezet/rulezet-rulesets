rule hunt_credaccess_iis {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" nocase
 $a2 = "connectionStrings" nocase
 $a3 = "web.config" nocase
 $a4 = "-pdf" nocase
 $b1 = "appcmd.exe" nocase
 $b2 = "/text:password"
condition: (all of ($a*) or all of ($b*))
}