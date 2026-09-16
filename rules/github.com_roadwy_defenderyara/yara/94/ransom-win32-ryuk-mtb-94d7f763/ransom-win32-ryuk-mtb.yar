rule Ransom_Win32_Ryuk_MTB{
	meta:
		description = "Ransom:Win32/Ryuk!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 70 61 73 73 77 6f 72 64 20 3d 20 27 } 		$a_01_1 = {24 74 6f 72 6c 69 6e 6b 20 3d 20 27 } 		$a_01_2 = {72 00 65 00 70 00 2e 00 65 00 78 00 65 00 } 		$a_01_3 = {52 00 45 00 50 00 } 		$a_01_4 = {52 59 55 4b 54 4d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}