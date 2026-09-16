rule Trojan_Win32_PonyStealer_AE_MTB_3{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 6e d0 0f 6e d0 0f 6e d0 90 13 [0-15] 46 [0-15] 8b 0f [0-15] 0f 6e c6 [0-15] 0f 6e c9 [0-15] 0f ef c8 [0-15] 0f 7e c9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}