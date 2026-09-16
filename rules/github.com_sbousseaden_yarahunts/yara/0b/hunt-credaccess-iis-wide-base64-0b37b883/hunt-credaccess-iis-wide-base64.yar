rule hunt_credaccess_iis_wide_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" wide base64
 $a2 = "connectionStrings" wide base64
 $a3 = "web.config" wide base64
 $a4 = "-pdf" wide base64
 $b1 = "appcmd.exe" wide base64
 $b2 = "/text:password" wide base64
condition: (3 of ($a*) or all of ($b*))
}