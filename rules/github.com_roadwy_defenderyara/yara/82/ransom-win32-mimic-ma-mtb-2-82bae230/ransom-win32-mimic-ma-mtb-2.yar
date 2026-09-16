rule Ransom_Win32_Mimic_MA_MTB_2{
	meta:
		description = "Ransom:Win32/Mimic.MA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 6c 66 44 65 6c 65 74 65 } 		$a_01_1 = {68 69 64 63 6f 6e } 		$a_01_2 = {45 76 65 72 79 74 68 69 6e 67 36 34 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}