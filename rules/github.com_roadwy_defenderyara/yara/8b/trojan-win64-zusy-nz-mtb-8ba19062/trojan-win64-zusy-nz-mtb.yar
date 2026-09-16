rule Trojan_Win64_Zusy_NZ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 75 73 20 4c 6f 61 64 65 72 2e 70 64 62 } 		$a_01_1 = {4b 65 79 20 64 6f 65 73 6e 74 20 65 78 69 73 74 20 21 } 		$a_01_2 = {64 73 63 2e 67 67 2f 72 69 76 65 } 		$a_01_3 = {48 75 73 43 6c 61 73 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}