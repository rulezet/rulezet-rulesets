rule Ransom_Win32_FileCoder_AMTB{
	meta:
		description = "Ransom:Win32/FileCoder!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {45 6e 74 65 72 20 63 6f 6e 66 69 72 6d 61 74 69 6f 6e 20 6f 66 20 70 61 79 6d 65 6e 74 } 		$a_80_1 = {50 61 79 6d 65 6e 74 20 6e 6f 74 20 72 65 63 65 69 76 65 64 } 		$a_80_2 = {54 6f 20 6f 70 65 6e 20 50 43 2c 20 70 6c 65 61 73 65 20 73 65 6e 64 20 24 31 30 30 } 		$a_80_3 = {50 43 20 69 73 20 6e 6f 77 20 70 72 6f 63 65 73 73 65 64 21 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}