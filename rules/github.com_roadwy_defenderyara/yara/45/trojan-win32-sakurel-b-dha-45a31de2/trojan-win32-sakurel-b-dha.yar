rule Trojan_Win32_Sakurel_B_dha{
	meta:
		description = "Trojan:Win32/Sakurel.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73 00 } 		$a_00_1 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 2f 71 20 22 25 73 22 00 } 		$a_00_2 = {3f 70 68 6f 74 6f 69 64 3d 00 } 		$a_03_3 = {68 f4 01 00 00 ff 15 ?? ?? ?? ?? 81 c3 00 90 3b 9d ?? ?? ff ff 0f 86 ?? ?? ff ff } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*2) >=3
 
}