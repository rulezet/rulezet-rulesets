rule Trojan_Win32_Zbot_DM_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {fe c3 36 8a 94 2b 00 fc ff ff 02 c2 36 8a 8c 28 00 fc ff ff 36 88 8c 2b 00 fc ff ff 36 88 94 28 00 fc ff ff 02 ca 36 8a 8c 29 00 fc ff ff 30 0e 46 4f 75 cc } 		$a_01_1 = {44 65 63 72 79 70 74 4d 65 73 73 61 67 65 } 		$a_01_2 = {48 4f 53 54 32 3a 38 30 2e 38 35 2e 38 34 2e 37 39 } 		$a_01_3 = {68 74 74 70 73 3a 2f 2f 69 70 34 2e 73 65 65 69 70 2e 6f 72 67 } 		$a_01_4 = {31 39 34 2e 31 30 39 2e 32 30 36 2e 32 31 32 } 		$a_01_5 = {31 33 31 2e 31 38 38 2e 34 30 2e 31 38 39 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}