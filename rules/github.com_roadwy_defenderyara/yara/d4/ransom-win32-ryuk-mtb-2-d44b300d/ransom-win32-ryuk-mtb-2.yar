rule Ransom_Win32_Ryuk_MTB_2{
	meta:
		description = "Ransom:Win32/Ryuk!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 70 61 73 73 77 6f 72 64 20 3d 20 27 } 		$a_01_1 = {24 74 6f 72 6c 69 6e 6b 20 3d 20 27 } 		$a_01_2 = {52 59 55 4b 54 4d } 		$a_01_3 = {4e 74 64 6c 6c 2e 64 6c 6c } 		$a_01_4 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}