rule Trojan_Win64_EternalSunshine_A_dha{
	meta:
		description = "Trojan:Win64/EternalSunshine.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 3a 5c 6d 6b 6c 67 73 5c } 		$a_01_1 = {43 6d 66 63 6d 6b 6c 67 44 6c 67 } 		$a_01_2 = {43 6d 66 63 6d 6b 6c 67 41 70 70 } 		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 6b 65 65 70 61 73 73 2e 65 78 65 20 2f 74 20 2f 66 } 		$a_01_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 73 76 65 68 6f 73 74 2e 65 78 65 20 2f 74 20 2f 66 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}