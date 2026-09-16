rule Trojan_BAT_Small_EC_MTB_2{
	meta:
		description = "Trojan:BAT/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 43 6f 6d 6d 6f 6e 2f 73 6e 63 6e 78 77 75 74 64 68 77 78 2e 61 73 70 78 } 		$a_81_1 = {38 65 64 62 32 33 31 36 30 64 31 35 37 31 61 30 } 		$a_81_2 = {2f 43 6f 6d 6d 6f 6e 2f 75 79 69 73 67 68 67 6f 66 77 66 66 2e 61 73 70 78 } 		$a_81_3 = {48 74 74 70 53 65 72 76 65 72 55 74 69 6c 69 74 79 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}