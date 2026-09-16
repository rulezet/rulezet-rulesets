rule Trojan_Win32_Qbot_RTA_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {4d 69 66 44 74 7a 61 4d 68 67 47 } 		$a_80_1 = {5a 48 78 62 45 54 6f 70 75 4f 49 } 		$a_80_2 = {67 55 6d 61 6d 58 50 } 		$a_80_3 = {6a 4b 75 45 6b 68 62 4d 6b 4d 68 59 4b 47 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}