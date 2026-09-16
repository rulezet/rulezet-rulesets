rule Trojan_Win64_IcedId_FA_MTB{
	meta:
		description = "Trojan:Win64/IcedId.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 38 79 6f 6f 5a } 		$a_01_1 = {76 4b 69 46 79 30 } 		$a_01_2 = {77 78 6c 79 69 42 68 70 57 } 		$a_01_3 = {78 53 73 6b 4d 47 79 } 		$a_01_4 = {79 67 61 73 62 66 67 74 66 68 6a 61 73 6b 66 79 61 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}