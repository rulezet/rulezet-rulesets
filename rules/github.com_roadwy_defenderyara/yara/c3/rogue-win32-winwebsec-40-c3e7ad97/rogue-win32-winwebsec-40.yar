rule Rogue_Win32_Winwebsec_40{
	meta:
		description = "Rogue:Win32/Winwebsec,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 50 6f 72 6e 6f 54 75 62 65 58 58 58 5c 41 6e 74 69 76 69 72 75 73 } 		$a_01_1 = {2c 20 50 6f 72 6e 6f 54 75 62 65 58 58 58 } 		$a_01_2 = {5c 73 65 72 76 69 63 65 2e 65 78 65 } 		$a_01_3 = {20 41 6e 74 69 76 69 72 75 73 3f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}