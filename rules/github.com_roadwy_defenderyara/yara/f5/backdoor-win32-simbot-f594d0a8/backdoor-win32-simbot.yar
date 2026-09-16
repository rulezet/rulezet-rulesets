rule Backdoor_Win32_Simbot{
	meta:
		description = "Backdoor:Win32/Simbot,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {56 8b 45 0c 8d 8d e8 fe ff ff 8d 34 03 e8 ?? ?? ?? ?? 30 06 43 3b 5d 10 7c e7 5e } 		$a_01_1 = {2f 25 73 2e 70 68 70 3f 69 64 3d 25 30 36 64 25 73 } 		$a_01_2 = {25 63 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 } 		$a_01_3 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 } 	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}