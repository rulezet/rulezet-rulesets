rule Trojan_Win64_Emotet_ER_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_1 = {79 61 68 61 76 53 6f 64 75 6b 75 2e 74 78 74 } 		$a_01_2 = {62 54 6c 5a 63 33 64 53 54 44 4a 50 52 7a 4a 6a 49 55 39 } 		$a_01_3 = {51 50 54 6f 49 6c } 		$a_01_4 = {51 6e 69 6d 51 73 43 42 6b 6e 69 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}