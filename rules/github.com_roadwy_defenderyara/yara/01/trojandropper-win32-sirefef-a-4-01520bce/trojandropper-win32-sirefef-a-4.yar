rule TrojanDropper_Win32_Sirefef_A_4{
	meta:
		description = "TrojanDropper:Win32/Sirefef.A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 39 4e 88 8c 05 ?? ?? ff ff 48 85 f6 77 eb 01 55 f8 ff 4d fc 6a 40 59 8d b5 ?? ?? ff ff f3 a5 75 d1 6a 0a 6a 66 } 		$a_03_1 = {8b f8 85 ff 74 4e 6a 10 58 e8 ?? ?? 00 00 8b f4 8d 47 60 50 6a 20 83 c6 f0 56 ff 15 ?? ?? 40 00 56 6a 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}