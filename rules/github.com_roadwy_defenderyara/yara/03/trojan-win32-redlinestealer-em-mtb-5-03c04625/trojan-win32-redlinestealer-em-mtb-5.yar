rule Trojan_Win32_RedLineStealer_EM_MTB_5{
	meta:
		description = "Trojan:Win32/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {29 c3 89 d8 c0 c0 02 83 f0 62 83 e8 0e f7 d0 d0 c8 88 44 15 c1 } 		$a_01_1 = {6e 75 72 74 6f 79 63 6b 74 6f 71 6f 58 52 4a 57 51 4f 52 4a 56 6f 71 77 6a 72 69 78 6e 71 77 69 72 6f 6b 76 4a 45 4f 57 54 4e 4d 78 6f 77 65 74 6b 6f 6e 77 76 6f } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}