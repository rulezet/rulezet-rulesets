rule Trojan_AndroidOS_Zitmo_B_2{
	meta:
		description = "Trojan:AndroidOS/Zitmo.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 6f 3d 25 73 26 69 3d 25 73 26 6d 3d 25 73 26 61 69 64 3d 25 73 26 68 3d 25 73 26 76 3d 25 73 } 		$a_01_1 = {6b 61 76 64 61 74 61 2e 64 62 } 		$a_01_2 = {68 3d 2d 71 2d 2d 3d 2d 2d 2d 2d 74 71 2d 2d 74 2d 71 3d 70 2d 71 3d 3a 2d 3d 3d 71 2f 71 2f 71 72 71 6f 71 75 2d 3d 74 2d 69 3d 71 6e 71 2d 67 71 3d 2d 73 71 6d 3d 2d 73 71 2e 2d 3d 63 2d 3d 71 6f 2d 6d 71 2f 3d 2d 71 7a 71 2e 2d 71 3d 70 3d 71 68 2d 70 3d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}