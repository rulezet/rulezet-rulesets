rule Trojan_MacOS_NukeSped_D_MTB{
	meta:
		description = "Trojan:MacOS/NukeSped.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 69 6e 67 6f 74 72 61 64 65 2e 63 6f 6d 2f 75 70 64 61 74 65 5f 63 6f 69 6e 67 6f 74 72 61 64 65 2e 70 68 70 } 		$a_00_1 = {2f 70 72 69 76 61 74 65 2f 74 6d 70 2f 75 70 64 61 74 65 63 6f 69 6e 67 6f 74 72 61 64 65 } 		$a_00_2 = {69 73 44 6f 77 6e 6c 6f 61 64 } 		$a_00_3 = {6b 75 70 61 79 5f 75 70 64 61 74 65 72 5f 6d 61 63 5f 6e 65 77 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}