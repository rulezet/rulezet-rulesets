rule Trojan_MacOS_HashBreaker_A_MTB_2{
	meta:
		description = "Trojan:MacOS/HashBreaker.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 75 6d 70 4b 65 79 43 68 61 69 6e } 		$a_00_1 = {55 70 6c 6f 61 64 4b 65 79 63 68 61 69 6e } 		$a_00_2 = {44 65 63 72 79 70 74 4b 65 79 63 68 61 69 6e } 		$a_00_3 = {45 78 74 72 61 63 74 53 61 66 65 53 74 6f 72 61 67 65 50 61 73 73 77 6f 72 64 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}