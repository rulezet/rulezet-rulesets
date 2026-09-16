rule Trojan_Win32_Fareit_VL_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 4c 24 04 c1 64 24 04 ?? 8b 44 24 0c 01 44 24 04 89 0c 24 c1 2c 24 ?? 8b 44 24 14 01 04 24 8b 44 24 10 03 c1 33 04 24 33 44 24 04 83 c4 ?? c3 } 		$a_02_1 = {8b 44 24 24 89 78 04 ?? ?? ?? 89 18 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}