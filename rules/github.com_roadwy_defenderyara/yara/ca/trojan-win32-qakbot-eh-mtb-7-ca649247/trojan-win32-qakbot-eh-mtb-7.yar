rule Trojan_Win32_Qakbot_EH_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 55 65 69 4f 51 6c 64 79 73 61 } 		$a_01_1 = {63 69 78 64 53 45 4a 68 6a 4a } 		$a_01_2 = {5a 78 47 73 53 6d 41 49 65 64 4f 53 } 		$a_01_3 = {4e 57 4a 4c 6a 52 46 41 58 62 77 74 75 64 71 } 		$a_01_4 = {47 74 66 62 73 44 7a 41 46 69 4a 68 77 49 57 6e 6f 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}