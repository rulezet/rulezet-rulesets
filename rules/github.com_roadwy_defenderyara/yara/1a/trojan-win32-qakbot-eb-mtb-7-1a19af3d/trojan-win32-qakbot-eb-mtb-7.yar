rule Trojan_Win32_Qakbot_EB_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 58 66 50 38 33 36 71 36 } 		$a_01_1 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } 		$a_01_2 = {47 72 58 70 34 30 } 		$a_01_3 = {53 6b 6a 39 32 57 } 		$a_01_4 = {57 49 75 64 4b 33 39 38 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}