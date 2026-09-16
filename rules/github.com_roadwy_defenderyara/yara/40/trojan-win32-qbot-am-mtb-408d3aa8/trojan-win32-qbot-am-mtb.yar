rule Trojan_Win32_Qbot_AM_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 4c 52 35 33 73 64 53 57 } 		$a_01_1 = {41 4d 69 48 51 37 } 		$a_01_2 = {42 56 62 49 56 63 34 67 32 } 		$a_01_3 = {42 5a 38 57 6b 43 } 		$a_01_4 = {42 66 33 50 35 45 36 } 		$a_01_5 = {43 4e 79 35 73 71 33 4c 4d 72 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}