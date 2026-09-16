rule Trojan_Win32_Trickbot_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 "
		
	strings :
		$a_01_0 = {5e 32 3f 53 6e 72 77 6b 5a 53 7a 70 75 50 49 } 		$a_01_1 = {46 75 63 6b 20 44 65 66 } 		$a_01_2 = {47 65 74 4b 65 79 53 74 61 74 65 } 		$a_01_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } 		$a_01_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } 		$a_01_5 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f 41 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=23
 
}