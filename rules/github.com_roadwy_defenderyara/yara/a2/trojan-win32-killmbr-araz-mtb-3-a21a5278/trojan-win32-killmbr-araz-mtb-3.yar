rule Trojan_Win32_KillMBR_ARAZ_MTB_3{
	meta:
		description = "Trojan:Win32/KillMBR.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 64 65 73 74 6f 72 79 65 64 21 } 		$a_01_1 = {5c 57 69 6e 64 6f 77 53 6d 61 73 68 65 72 2e 70 64 62 } 		$a_00_2 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}