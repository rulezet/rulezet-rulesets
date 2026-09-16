rule Ransom_Win32_Firecrypt_A_2{
	meta:
		description = "Ransom:Win32/Firecrypt.A,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 66 00 69 00 72 00 65 00 63 00 72 00 79 00 70 00 74 00 } 		$a_01_1 = {2e 00 64 00 6f 00 63 00 78 00 00 09 2e 00 63 00 73 00 76 00 00 09 2e 00 73 00 71 00 6c 00 } 		$a_01_2 = {5c 00 53 00 79 00 73 00 57 00 69 00 6e 00 33 00 32 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}