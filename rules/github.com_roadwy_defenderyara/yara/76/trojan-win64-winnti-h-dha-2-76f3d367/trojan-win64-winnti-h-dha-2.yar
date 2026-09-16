rule Trojan_Win64_Winnti_H_dha_2{
	meta:
		description = "Trojan:Win64/Winnti.H!dha,SIGNATURE_TYPE_PEHSTR,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 48 43 72 65 61 74 65 49 74 65 6d 46 72 6f 6d 50 61 72 73 69 6e 67 4e 61 6d } 		$a_01_1 = {6f 74 66 6b 74 79 2e 64 61 74 } 		$a_01_2 = {77 6f 72 6b 5f 73 74 61 72 74 } 		$a_01_3 = {77 6f 72 6b 5f 65 6e 64 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=100
 
}