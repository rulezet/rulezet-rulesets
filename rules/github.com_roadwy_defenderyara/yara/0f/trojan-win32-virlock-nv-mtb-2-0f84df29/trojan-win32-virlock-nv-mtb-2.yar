rule Trojan_Win32_Virlock_NV_MTB_2{
	meta:
		description = "Trojan:Win32/Virlock.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 42 46 47 49 83 f9 00 0f 85 ed ff ff ff e9 2a 00 00 00 } 		$a_03_1 = {89 07 8b f8 8b df b9 ?? 03 00 00 ba ?? 00 00 00 e9 be ff ff ff } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}