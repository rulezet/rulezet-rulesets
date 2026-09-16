rule Trojan_Win32_Qbot_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {54 66 74 76 67 79 62 47 74 66 76 67 79 62 } 		$a_80_1 = {4b 6a 69 6e 68 75 44 64 72 66 74 } 		$a_80_2 = {49 68 75 6e 45 64 66 64 66 67 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}