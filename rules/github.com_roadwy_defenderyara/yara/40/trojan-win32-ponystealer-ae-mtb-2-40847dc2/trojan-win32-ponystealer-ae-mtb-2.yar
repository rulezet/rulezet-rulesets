rule Trojan_Win32_PonyStealer_AE_MTB_2{
	meta:
		description = "Trojan:Win32/PonyStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6e c6 [0-15] 66 0f 6e c9 [0-15] 66 0f ef c8 [0-15] 66 0f 7e c9 [0-25] 90 13 0f 77 [0-15] [0-15] ff 37 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}