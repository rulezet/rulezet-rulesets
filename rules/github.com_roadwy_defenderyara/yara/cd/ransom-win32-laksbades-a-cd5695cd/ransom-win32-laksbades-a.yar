rule Ransom_Win32_Laksbades_A{
	meta:
		description = "Ransom:Win32/Laksbades.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {46 8b c6 03 c0 50 8d 45 ?? 8b 0d ?? ?? ?? ?? 8b 93 cc 03 00 00 e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 6a 01 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 8b 45 fc 50 e8 ?? ?? ?? ?? 85 c0 75 03 83 cf ff 8b 45 fc 50 e8 } 		$a_00_1 = {22 00 2d 00 6b 00 65 00 79 00 20 00 } 		$a_02_2 = {2e 00 70 00 68 00 70 00 [0-80] 64 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 68 00 74 00 6d 00 6c 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}