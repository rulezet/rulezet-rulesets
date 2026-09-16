rule Trojan_Win32_Guloader_RPP_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f dc e5 ff 34 32 [0-20] 90 13 [0-20] 81 34 24 [0-20] 8f 04 30 [0-20] 83 de [0-20] 90 13 [0-20] 83 d6 ?? 0f 8d ?? ff ff ff } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}