rule Rogue_Win32_Onescan_11{
	meta:
		description = "Rogue:Win32/Onescan,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {c1 ef 0c 47 c1 e7 0c 57 89 7e 10 e8 ?? ?? ?? ?? 83 c4 04 89 46 08 8b 4e 10 8b 7e 08 8b d1 33 c0 c1 e9 02 f3 ab } 		$a_01_1 = {2e 63 6f 2e 6b 72 2f 41 50 50 2f 73 74 61 74 2e 70 68 70 3f 76 31 3d } 		$a_01_2 = {2e 63 6f 2e 6b 72 2f 41 50 50 2f 70 66 5f 63 6b 2e 70 68 70 3f 76 31 3d } 		$a_01_3 = {4e 30 6c 59 57 44 64 73 64 33 39 32 64 48 64 70 62 44 5a 34 63 48 68 48 64 55 55 3d } 		$a_01_4 = {6d 62 6b 2e 70 68 70 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}