rule Trojan_Win32_Qakbot_AM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 33 6a 43 6e 53 61 71 } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_2 = {45 4d 62 76 46 5a 4d 69 64 64 } 		$a_01_3 = {45 51 34 65 50 62 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}