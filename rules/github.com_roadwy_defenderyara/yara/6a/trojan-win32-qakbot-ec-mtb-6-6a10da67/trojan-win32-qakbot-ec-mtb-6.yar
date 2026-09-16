rule Trojan_Win32_Qakbot_EC_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_1 = {30 7a 33 44 2e 64 6c 6c } 		$a_01_2 = {41 50 59 79 6c 49 39 30 } 		$a_01_3 = {42 4a 39 76 59 54 49 5a } 		$a_01_4 = {43 38 36 37 7a 4f 53 6f } 		$a_01_5 = {44 6b 71 70 79 45 6a } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}