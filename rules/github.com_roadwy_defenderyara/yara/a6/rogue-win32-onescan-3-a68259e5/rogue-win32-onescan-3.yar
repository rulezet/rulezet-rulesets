rule Rogue_Win32_Onescan_3{
	meta:
		description = "Rogue:Win32/Onescan,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {d1 fe ff d5 2b c7 6a 05 99 2b c2 } 		$a_01_1 = {2f 62 69 6c 6c 5f 6d 6f 62 69 6c 2f } 		$a_01_2 = {2f 73 65 74 74 6c 65 2e 70 68 70 3f } 		$a_01_3 = {3f 73 74 72 50 43 3d 25 73 26 73 74 72 49 44 3d 25 73 } 		$a_01_4 = {26 73 74 72 53 69 74 65 3d 25 73 } 		$a_00_5 = {5c 5b 55 73 65 72 53 63 61 6e 2d } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=14
 
}