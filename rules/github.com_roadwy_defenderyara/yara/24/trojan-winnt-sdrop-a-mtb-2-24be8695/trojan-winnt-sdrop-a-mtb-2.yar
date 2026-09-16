rule Trojan_WinNT_SDrop_A_MTB_2{
	meta:
		description = "Trojan:WinNT/SDrop.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 76 6f 71 6d 71 72 74 70 6a 62 2e 6a 61 76 61 } 		$a_00_1 = {72 65 73 6f 75 72 63 65 73 2f 67 62 70 61 7a 78 74 64 78 63 } 		$a_00_2 = {61 6f 78 63 64 6e 72 72 63 6c 2e 76 62 73 } 		$a_02_3 = {52 75 6e 74 69 6d 65 [0-05] 65 78 65 63 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}