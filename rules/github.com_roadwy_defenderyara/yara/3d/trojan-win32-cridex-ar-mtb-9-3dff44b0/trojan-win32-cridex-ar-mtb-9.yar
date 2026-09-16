rule Trojan_Win32_Cridex_AR_MTB_9{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 74 24 20 8d 34 09 2b f0 8b ca 81 c6 71 f2 fe ff 03 f2 33 d2 89 74 24 34 85 c9 0f 94 c2 89 54 24 3c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}