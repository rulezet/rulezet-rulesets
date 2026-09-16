rule Rogue_Win32_Onescan_6{
	meta:
		description = "Rogue:Win32/Onescan,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 2f 62 69 6c 6c 5f 6d 6f 62 69 6c 2f 63 6c 6f 73 65 57 69 6e 2e 68 74 6d 00 00 00 00 6c 6f 67 69 6e 5f 6f 6b 6f 6b 2e 68 74 6d 00 } 		$a_03_1 = {2f 73 65 74 74 6c 65 2e 70 68 70 3f 73 74 72 49 44 3d (00|25 73 26 73 74 72 50 43) } 		$a_03_2 = {5f 6e 69 63 00 90 05 03 01 00 25 59 2d 25 6d 2d 25 64 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}