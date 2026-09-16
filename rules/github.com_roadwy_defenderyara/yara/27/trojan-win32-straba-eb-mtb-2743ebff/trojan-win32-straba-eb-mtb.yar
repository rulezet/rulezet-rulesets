rule Trojan_Win32_Straba_EB_MTB{
	meta:
		description = "Trojan:Win32/Straba.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 47 42 48 4e 4a 4d 4b 2e 44 4c 4c } 		$a_01_1 = {46 66 67 62 48 67 79 62 68 } 		$a_01_2 = {46 67 62 79 68 6e 4b 6a 67 76 } 		$a_01_3 = {54 74 66 76 79 67 62 4b 68 62 67 66 } 		$a_01_4 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}