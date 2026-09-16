rule Trojan_Win32_Guloader_RPR_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 26 26 26 26 26 26 26 26 26 26 66 31 0c 1f d8 cc db e2 eb 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}