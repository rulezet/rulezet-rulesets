rule Trojan_Win32_Qakbot_EA_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 44 79 5a } 		$a_01_1 = {47 48 51 76 42 35 38 68 32 45 } 		$a_01_2 = {4d 71 61 65 30 31 69 64 } 		$a_01_3 = {53 4e 69 66 43 77 32 34 32 4f 43 44 } 		$a_01_4 = {4c 47 76 35 49 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}