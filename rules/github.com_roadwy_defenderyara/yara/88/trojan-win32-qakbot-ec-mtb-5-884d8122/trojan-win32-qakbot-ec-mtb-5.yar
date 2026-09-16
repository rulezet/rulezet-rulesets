rule Trojan_Win32_Qakbot_EC_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 75 63 4b 4a 36 36 30 } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_2 = {4f 65 4b 4c 72 39 4c } 		$a_01_3 = {50 49 6c 70 70 6e 33 35 69 32 } 		$a_01_4 = {57 68 7a 78 71 59 30 4a 72 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}