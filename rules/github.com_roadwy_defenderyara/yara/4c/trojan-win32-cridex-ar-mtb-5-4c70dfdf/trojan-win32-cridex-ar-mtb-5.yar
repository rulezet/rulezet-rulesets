rule Trojan_Win32_Cridex_AR_MTB_5{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c6 2b c3 83 e8 04 2b 44 24 28 83 44 24 18 04 83 c0 da 8b 3d ?? ?? ?? ?? 03 c6 83 6c 24 1c 01 89 44 24 14 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}