rule Ransom_Win32_Crowti_B{
	meta:
		description = "Ransom:Win32/Crowti.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 0c 68 01 00 01 00 6a 00 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 88 94 00 00 00 ff d1 89 45 f8 83 7d f8 00 } 		$a_01_1 = {9b 85 e7 e3 ca 85 53 0b } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}