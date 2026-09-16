rule Backdoor_Win32_Zegost_DE{
	meta:
		description = "Backdoor:Win32/Zegost.DE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 38 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 38 40 3b c6 72 de 5f 5b } 		$a_03_1 = {5c c6 44 24 ?? 6f c6 44 24 ?? 75 c6 44 24 ?? 72 c6 44 24 ?? 6c c6 44 24 ?? 6f c6 44 24 ?? 67 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 61 c6 44 24 ?? 74 c6 44 24 ?? 00 ff } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}