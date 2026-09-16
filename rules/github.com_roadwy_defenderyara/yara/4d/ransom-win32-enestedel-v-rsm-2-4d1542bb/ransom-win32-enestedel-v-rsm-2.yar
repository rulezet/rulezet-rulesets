rule Ransom_Win32_Enestedel_V_rsm_2{
	meta:
		description = "Ransom:Win32/Enestedel.V!rsm,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 7d ?? 8b 45 ?? 8a 8a ?? ?? ?? ?? c0 e1 03 88 08 8b 4d ?? 30 08 41 3b ce 89 4d ?? 7c d7 } 		$a_03_1 = {6a 03 6a 00 ff 30 51 68 ?? ?? ?? ?? ff 55 ?? 8b f0 6a 00 56 ff 55 } 		$a_03_2 = {6a 04 8b f0 57 c7 06 00 80 00 00 ff 55 ?? 6a 04 57 89 45 ?? c7 00 01 00 00 00 ff 55 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}