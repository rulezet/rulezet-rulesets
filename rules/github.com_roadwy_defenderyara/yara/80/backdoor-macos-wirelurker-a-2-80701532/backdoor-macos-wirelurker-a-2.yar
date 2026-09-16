rule Backdoor_MacOS_Wirelurker_A_2{
	meta:
		description = "Backdoor:MacOS/Wirelurker.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 44 65 72 69 76 65 64 44 61 74 61 2f 6d 79 50 72 6f 6a 65 63 74 2d 62 65 6d 70 6e 75 75 6e 79 73 78 6f 61 66 63 64 65 6f 6b 75 76 76 66 69 67 6d 7a 65 2f } 		$a_00_1 = {2f 53 79 73 74 65 6d 2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 44 61 65 6d 6f 6e 73 2f 63 6f 6d 2e 61 70 70 6c 65 2e 4d 61 69 6c 53 65 72 76 69 63 65 41 67 65 6e 74 48 65 6c 70 65 72 2e 70 6c 69 73 74 } 		$a_00_2 = {72 6d 20 2d 72 66 20 2f 76 61 72 2f 64 62 2f 6c 61 75 6e 63 68 64 2e 64 62 2f 63 6f 6d 2e 61 70 70 6c 65 2e 6c 61 75 6e 63 68 64 2f } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}