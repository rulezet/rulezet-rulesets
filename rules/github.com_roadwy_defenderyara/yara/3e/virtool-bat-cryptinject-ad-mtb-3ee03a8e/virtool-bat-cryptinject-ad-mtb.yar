rule VirTool_BAT_CryptInject_AD_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 75 70 65 75 2e 64 6c 6c } 		$a_01_1 = {73 77 65 74 79 } 		$a_01_2 = {63 73 68 61 72 70 73 74 75 62 } 		$a_01_3 = {43 6c 75 62 62 69 6e 67 } 		$a_01_4 = {73 65 74 79 } 		$a_01_5 = {35 2e 32 31 2e 31 2e 33 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}