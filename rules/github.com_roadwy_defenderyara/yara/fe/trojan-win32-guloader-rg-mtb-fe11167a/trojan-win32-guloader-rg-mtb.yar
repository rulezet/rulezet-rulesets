rule Trojan_Win32_GuLoader_RG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6c 76 62 72 79 6c 6c 75 70 70 65 74 73 } 		$a_01_1 = {41 6e 74 69 6b 76 69 74 65 74 73 66 6f 72 72 65 74 6e 69 6e 67 65 72 32 } 		$a_01_2 = {41 6d 66 69 62 69 65 74 61 6e 6b } 		$a_00_3 = {46 00 4c 00 75 00 78 00 4f 00 69 00 6c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}