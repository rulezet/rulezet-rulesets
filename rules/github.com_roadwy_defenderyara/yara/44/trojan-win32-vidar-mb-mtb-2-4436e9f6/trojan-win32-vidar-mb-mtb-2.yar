rule Trojan_Win32_Vidar_MB_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 2e e0 65 9c cc 87 bf a4 fa 10 10 61 6c a1 01 a3 3d a3 ab 23 f9 15 47 10 e5 90 4e 08 24 c2 cc 20 75 3a 4d d9 c7 8c f9 68 50 40 f6 bb fd 25 46 } 		$a_01_1 = {6b 71 4a d1 2b db 23 90 30 d5 65 cb f0 2a b6 ad 70 4b 27 c2 60 36 13 10 8d 35 a1 8b 20 4c be 7e e8 32 b7 9c 1b fc 29 4f 9a 28 85 0f 28 01 1e bd } 		$a_01_2 = {e0 00 02 01 0b 01 0a 00 00 ee 03 00 00 e8 } 		$a_01_3 = {2e 74 68 65 6d 69 64 61 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1) >=16
 
}