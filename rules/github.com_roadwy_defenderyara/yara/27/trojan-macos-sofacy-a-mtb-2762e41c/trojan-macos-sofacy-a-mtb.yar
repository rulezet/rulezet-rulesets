rule Trojan_MacOS_Sofacy_A_MTB{
	meta:
		description = "Trojan:MacOS/Sofacy.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e 61 70 70 6c 65 2e 75 70 64 61 74 65 72 2e 70 6c 69 73 74 } 		$a_00_1 = {3c 73 74 72 69 6e 67 3e 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f 64 75 66 68 3c 2f 73 74 72 69 6e 67 3e } 		$a_00_2 = {2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f 73 74 61 72 74 2e 73 68 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}