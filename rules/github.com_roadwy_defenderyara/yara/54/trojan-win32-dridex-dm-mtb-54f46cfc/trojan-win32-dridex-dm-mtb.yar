rule Trojan_Win32_Dridex_DM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 b9 ca b1 66 8b 54 24 28 66 29 d1 66 89 4c 24 6a 0f b6 00 3d b8 } 		$a_01_1 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } 		$a_01_2 = {41 64 64 4a 6f 62 57 } 		$a_01_3 = {53 48 45 6e 75 6d 65 72 61 74 65 55 6e 72 65 61 64 4d 61 69 6c 41 63 63 6f 75 6e 74 73 57 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=19
 
}