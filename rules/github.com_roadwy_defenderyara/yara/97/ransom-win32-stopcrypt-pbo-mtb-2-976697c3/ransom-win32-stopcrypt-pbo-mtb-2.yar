rule Ransom_Win32_StopCrypt_PBO_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.PBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c1 33 c2 83 3d [0-08] 89 44 24 ?? 75 } 		$a_03_1 = {2b f0 8b c6 d3 e8 89 74 24 ?? 03 d6 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? c1 e6 04 03 b4 24 ?? ?? ?? ?? 33 f2 81 3d [0-08] 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}