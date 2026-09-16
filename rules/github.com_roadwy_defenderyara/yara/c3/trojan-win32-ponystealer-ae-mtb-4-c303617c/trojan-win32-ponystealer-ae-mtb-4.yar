rule Trojan_Win32_PonyStealer_AE_MTB_4{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 7e d2 85 [0-25] 90 13 [0-15] 46 [0-15] 8b 17 [0-15] 0f 6e fe [0-15] 90 18 0f 6e d2 [0-15] 0f ef d7 [0-15] c3 } 		$a_03_1 = {0f 7e d2 83 [0-25] 90 13 [0-15] 46 [0-15] 8b 17 [0-25] 90 18 0f 6e d2 [0-15] 0f ef d7 [0-15] c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}