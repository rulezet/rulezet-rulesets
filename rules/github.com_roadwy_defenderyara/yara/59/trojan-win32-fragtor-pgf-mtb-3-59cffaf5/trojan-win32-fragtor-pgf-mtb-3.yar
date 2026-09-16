rule Trojan_Win32_Fragtor_PGF_MTB_3{
	meta:
		description = "Trojan:Win32/Fragtor.PGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c1 83 e1 1f 0f b6 89 ?? ?? ?? ?? 30 0c 06 40 3d 00 9e 00 00 72 e9 } 		$a_03_1 = {89 c1 83 e1 1f 0f b6 89 ?? ?? ?? ?? 30 0c 07 40 3d 00 9e 00 00 75 e9 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}