rule Trojan_Win32_Azorult_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 48 07 00 00 75 ?? 89 3d ?? ?? ?? ?? 8b ce e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 46 3b f0 72 } 		$a_00_1 = {b8 e1 bf 01 00 01 04 24 8b 04 24 8a 04 08 88 04 0a } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}