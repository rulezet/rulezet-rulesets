rule Trojan_Win32_PromptFilecoder_ZZB_MTB_2{
	meta:
		description = "Trojan:Win32/PromptFilecoder.ZZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {2e 67 65 74 65 6e 76 [0-10] 68 6f 73 74 6e 61 6d 65 } 		$a_02_1 = {2e 67 65 74 65 6e 76 [0-10] 75 73 65 72 70 72 6f 66 69 6c 65 } 		$a_02_2 = {2e 67 65 74 65 6e 76 [0-10] 68 6f 6d 65 } 		$a_02_3 = {69 6f 2e 70 6f 70 65 6e [0-10] 70 77 64 } 		$a_01_4 = {62 69 74 33 32 2e 62 78 6f 72 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}