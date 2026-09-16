rule Backdoor_Win32_Zegost_S{
	meta:
		description = "Backdoor:Win32/Zegost.S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_10_0 = {56 65 72 43 68 6b 3d 25 64 3a 45 4e 44 7c 25 73 } 		$a_10_1 = {25 73 2c 43 6c 65 61 72 53 65 6c 66 20 25 73 } 		$a_03_2 = {ff ff 83 fa 53 0f 85 ?? ?? 00 00 0f be 85 ?? ?? ff ff 83 f8 50 0f 85 ?? ?? 00 00 0f be 8d ?? ?? ff ff 83 f9 36 0f 85 ?? ?? 00 00 c6 85 64 ?? ?? ff 53 } 		$a_03_3 = {68 04 01 00 00 ff 15 ?? ?? ?? ?? c6 45 f8 25 c6 45 f9 73 c6 45 fa 5c c6 45 fb 25 c6 45 fc 64 c6 45 fd 00 } 	condition:
		((#a_10_0  & 1)*1+(#a_10_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=3
 
}