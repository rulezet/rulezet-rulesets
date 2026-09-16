rule Trojan_Win32_Qakbot_EM_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_1 = {6a 50 55 4d 4f 4f 55 69 45 2e 64 6c 6c } 		$a_01_2 = {41 6d 58 58 36 69 31 57 78 68 } 		$a_01_3 = {44 33 67 34 67 43 68 32 } 		$a_01_4 = {4a 6b 44 70 7a 44 4f 52 56 55 } 		$a_01_5 = {43 53 4e 5a 34 7a } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}