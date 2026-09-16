rule Ransom_Win32_Filecoder_AC_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 72 79 70 74 45 6e 63 72 79 70 74 20 66 61 69 6c 65 64 } 		$a_80_1 = {52 61 6e 73 6f 6d 5c 52 65 6c 65 61 73 65 5c 52 61 6e 73 6f 6d 2e 70 64 62 } 		$a_80_2 = {57 61 6c 6b 20 64 69 72 65 63 74 6f 72 79 20 63 72 79 70 74 20 66 61 69 6c 65 64 } 		$a_80_3 = {69 6e 69 74 5f 63 72 79 70 74 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}