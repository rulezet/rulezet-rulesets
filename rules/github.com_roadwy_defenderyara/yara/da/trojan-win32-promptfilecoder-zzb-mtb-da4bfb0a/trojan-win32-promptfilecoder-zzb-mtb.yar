rule Trojan_Win32_PromptFilecoder_ZZB_MTB{
	meta:
		description = "Trojan:Win32/PromptFilecoder.ZZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 6c 6d 2d 72 61 6e 73 6f 6d 2f 6c 6c 6d 2e 67 6f } 		$a_01_1 = {6d 61 69 6e 2e 73 65 72 76 65 72 69 70 } 		$a_01_2 = {6d 61 69 6e 2e 6d 6f 64 65 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}