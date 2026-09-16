rule Trojan_Win32_Qakbot_EB_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 58 50 42 4c 47 32 47 79 } 		$a_01_1 = {45 7a 4d 4e 62 51 4c } 		$a_01_2 = {48 6e 67 57 4d 30 78 } 		$a_01_3 = {4e 73 72 36 34 30 59 } 		$a_01_4 = {52 4f 55 4f 38 30 39 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}