rule Ransom_Win32_TeslaCrypt_GZZ_MTB_2{
	meta:
		description = "Ransom:Win32/TeslaCrypt.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 c7 89 f8 88 c1 8b 44 24 ?? 8b 7c 24 ?? 88 4c 24 ?? 29 c2 19 fe 89 54 24 ?? 89 74 24 ?? ?? ?? ?? ?? 8b 44 24 64 8a 4c 24 2f 88 08 e9 ?? ?? ?? ?? 8b 44 24 ?? 8b 4c 24 68 81 f1 0e 1c 00 00 39 c8 0f 87 } 		$a_01_1 = {43 6c 77 6f 6f 39 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}