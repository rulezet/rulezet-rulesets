rule Trojan_Win32_Guloader_RPP_MTB_5{
	meta:
		description = "Trojan:Win32/Guloader.RPP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4a 4a 4a 09 3c 01 de e0 de f7 eb 3f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}