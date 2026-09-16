rule Ransom_Win32_Filecoder_BB_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {62 63 6b 20 34 2e 30 20 32 30 32 30 2f 2f 31 31 2f 36 20 66 69 78 20 35 2e 76 69 72 75 73 20 62 79 20 7a 6e 6b 7a 7a } 		$a_81_2 = {2d 4c 49 42 47 43 43 57 33 32 2d 45 48 2d 53 4a 4c 4a 2d 47 54 48 52 2d 4d 49 4e 47 57 33 32 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}