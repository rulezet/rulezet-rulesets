rule Trojan_Win32_OffLoader_EN_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 00 65 00 65 00 74 00 68 00 62 00 75 00 62 00 62 00 6c 00 65 00 2e 00 69 00 63 00 75 00 2f 00 69 00 64 00 6f 00 2e 00 70 00 68 00 70 00 } 		$a_01_1 = {69 00 64 00 6f 00 2e 00 65 00 78 00 65 00 } 		$a_01_2 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}