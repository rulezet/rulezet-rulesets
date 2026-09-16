rule Trojan_WinNT_SDrop_A_MTB{
	meta:
		description = "Trojan:WinNT/SDrop.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 6e 76 6f 69 63 65 73 65 63 75 72 65 2e 6e 65 74 } 		$a_00_1 = {2f 66 6f 6f 74 65 72 2e 6a 70 67 } 		$a_00_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 64 72 76 72 33 32 2e 65 78 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}