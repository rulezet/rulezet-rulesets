rule Trojan_Win32_PonyStealer_AE_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6e c6 [0-25] 66 0f 6e c9 [0-40] 0f 7e c9 [0-25] 90 13 0f 77 [0-25] 46 [0-25] 8b 0f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}