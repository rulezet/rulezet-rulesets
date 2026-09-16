rule hunt_credaccess_iis_xor {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" wide xor
 $a2 = "connectionStrings" wide xor
 $a3 = "web.config" wide xor
 $a4 = "-pdf" wide xor
 $b1 = "appcmd.exe" wide xor
 $b2 = "/text:password" wide xor
condition: (all of ($a*) or all of ($b*))
}