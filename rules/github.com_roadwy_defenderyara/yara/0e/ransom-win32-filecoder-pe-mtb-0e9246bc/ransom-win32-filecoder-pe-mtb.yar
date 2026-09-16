rule Ransom_Win32_FileCoder_PE_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {52 45 41 44 4d 45 2e 74 78 74 } 		$a_00_1 = {53 6f 6d 65 20 66 69 6c 65 73 20 69 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } 		$a_00_2 = {70 6f 77 65 72 40 72 61 6e 73 6f 6d 77 61 72 65 2e 63 6f 6d } 		$a_02_3 = {5c 50 6f 77 65 72 52 61 6e 73 6f 6d 5c [0-10] 5c 50 6f 77 65 72 52 61 6e 73 6f 6d 2e 70 64 62 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}