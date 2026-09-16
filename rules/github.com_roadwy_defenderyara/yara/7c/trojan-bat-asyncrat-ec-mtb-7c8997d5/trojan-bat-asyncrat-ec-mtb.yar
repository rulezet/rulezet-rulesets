rule Trojan_BAT_AsyncRAT_EC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {41 73 79 6e 63 52 41 54 20 30 2e 34 } 		$a_81_1 = {64 71 71 69 74 64 61 69 2e 62 30 70 } 		$a_81_2 = {43 6f 6e 6e 65 63 74 65 64 21 } 		$a_81_3 = {49 6e 6a 65 63 74 } 		$a_81_4 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 31 20 26 20 44 65 6c } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}