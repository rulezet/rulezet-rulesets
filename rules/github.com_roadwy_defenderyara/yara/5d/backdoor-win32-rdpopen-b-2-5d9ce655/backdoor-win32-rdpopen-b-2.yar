rule Backdoor_Win32_RDPopen_B_2{
	meta:
		description = "Backdoor:Win32/RDPopen.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 06 6a 01 6a 02 8b 85 ?? ?? ?? ?? 8b 88 84 01 00 00 ff d1 } 		$a_03_1 = {ff d0 3d 33 27 00 00 75 ?? 6a 05 8b 4d 08 8b 91 24 01 00 00 ff d2 eb ?? 33 c0 } 		$a_00_2 = {7c 67 65 74 68 6f 73 74 6e 61 6d 65 } 		$a_00_3 = {6a 69 65 66 68 68 66 75 66 68 } 		$a_00_4 = {68 64 32 68 30 38 30 68 63 68 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}