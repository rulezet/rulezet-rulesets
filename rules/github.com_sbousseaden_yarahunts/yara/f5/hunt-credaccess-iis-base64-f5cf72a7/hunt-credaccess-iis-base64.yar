rule hunt_credaccess_iis_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" base64
 $a2 = "connectionStrings" base64
 $a3 = "web.config" base64
 $a4 = "-pdf" base64
 $b1 = "appcmd.exe" base64
 $b2 = "/text:password" base64
condition: (3 of ($a*) or all of ($b*))
}