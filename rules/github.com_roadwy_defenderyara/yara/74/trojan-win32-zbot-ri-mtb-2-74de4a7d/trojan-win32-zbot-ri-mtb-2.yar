rule Trojan_Win32_Zbot_RI_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 45 20 43 6f 6f 6b 69 65 73 3a } 		$a_01_1 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 55 66 5c 56 57 58 49 54 3c 41 4b 47 3c 42 } 		$a_01_2 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 62 63 5a } 		$a_01_3 = {66 6b 7b 76 74 65 6c 70 70 5d 68 67 5b 5f 5c 48 61 51 54 50 51 47 4d 4a } 		$a_01_4 = {66 6b 7b 76 74 65 6c 70 70 5d 68 67 5b 5f 5c 48 58 4d 5a 5b 51 52 49 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}