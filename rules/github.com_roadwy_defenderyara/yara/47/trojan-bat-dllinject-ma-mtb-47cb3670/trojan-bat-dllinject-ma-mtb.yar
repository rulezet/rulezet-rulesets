rule Trojan_BAT_DllInject_MA_MTB{
	meta:
		description = "Trojan:BAT/DllInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 0d 00 09 6f ?? ?? ?? 0a 72 0b 00 00 70 28 ?? ?? ?? 0a 13 04 11 04 13 05 11 05 2c 09 00 09 } 		$a_01_1 = {4c 61 75 6e 63 68 45 78 70 6c 6f 69 74 } 		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } 		$a_01_3 = {52 6f 62 6c 6f 78 5f 45 78 65 63 75 74 6f 72 5f 57 6f 6c 66 43 68 65 61 74 73 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}