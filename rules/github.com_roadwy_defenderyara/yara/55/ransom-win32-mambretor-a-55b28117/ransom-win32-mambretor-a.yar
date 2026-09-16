rule Ransom_Win32_Mambretor_A{
	meta:
		description = "Ransom:Win32/Mambretor.A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 44 43 32 32 5c 6e 65 74 70 61 73 73 2e 65 78 65 } 		$a_00_1 = {6e 65 74 20 75 73 65 72 20 2f 61 64 64 20 6d 79 74 68 62 75 73 74 65 72 73 } 		$a_01_2 = {68 00 64 00 30 00 00 00 73 74 61 72 74 20 68 61 72 64 20 64 72 69 76 65 20 65 6e 63 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}