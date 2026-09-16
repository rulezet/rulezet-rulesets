rule Ransom_Win32_Urausy_E{
	meta:
		description = "Ransom:Win32/Urausy.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 3e 53 45 4c 46 0f 84 ?? ?? ?? ?? 81 3e 00 50 4b 00 } 		$a_01_1 = {89 f7 83 c9 ff 31 c0 f2 ae c7 47 fb 2e 69 6e 69 56 ff 93 } 		$a_03_2 = {c7 01 00 10 00 00 6a 40 68 00 10 00 00 51 50 57 6a ff ff 93 ?? ?? 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}