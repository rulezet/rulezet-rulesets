rule Rogue_MacOS_X_FakeMacdef{
	meta:
		description = "Rogue:MacOS_X/FakeMacdef,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 40 2f 6d 61 63 2f 73 6f 66 74 2e 70 68 70 3f 61 66 66 69 64 3d 25 40 00 } 		$a_00_1 = {63 64 20 2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 3b 75 6e 7a 69 70 20 25 40 3b 72 6d 20 2d 72 66 20 5f 5f 4d 41 43 4f 53 58 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}