rule Trojan_MacOS_HashBreaker_A_MTB{
	meta:
		description = "Trojan:MacOS/HashBreaker.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 61 74 61 2e 57 61 6c 6c 65 74 73 } 		$a_01_1 = {4e 55 49 54 4b 41 5f 54 49 43 4b 45 52 } 		$a_00_2 = {64 61 74 61 2e 63 68 61 69 6e 62 72 65 61 6b 65 72 } 		$a_00_3 = {67 65 74 5f 63 6f 69 6e 6f 6d 69 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}