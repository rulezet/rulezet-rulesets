rule Trojan_Win32_Qakbot_EH_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 42 4b 67 6b 52 61 68 57 7a 59 } 		$a_01_1 = {52 61 6c 6c 6f 63 61 74 65 50 6f 73 69 74 69 6f 6e 73 } 		$a_01_2 = {52 61 70 70 6c 79 49 6e 73 65 72 74 69 6f 6e 73 } 		$a_01_3 = {4c 45 47 6c 79 70 68 53 74 6f 72 61 67 65 } 		$a_01_4 = {76 62 65 6e 67 } 		$a_01_5 = {7a 63 63 6d 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}