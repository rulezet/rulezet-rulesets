rule Trojan_BAT_Small_EC_MTB{
	meta:
		description = "Trojan:BAT/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {56 6d 74 6b 52 32 56 72 4f 56 68 57 62 6d 73 39 } 		$a_81_1 = {34 39 66 37 37 30 36 35 38 63 36 62 32 37 61 37 } 		$a_81_2 = {70 61 79 6c 6f 61 64 } 		$a_81_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } 		$a_81_4 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}