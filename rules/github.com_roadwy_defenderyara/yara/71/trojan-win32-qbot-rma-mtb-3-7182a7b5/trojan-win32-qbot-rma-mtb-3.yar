rule Trojan_Win32_Qbot_RMA_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {4a 67 4e 6e 58 47 64 68 } 		$a_80_1 = {69 71 64 6f 65 45 59 4f 48 65 } 		$a_80_2 = {69 73 78 46 42 44 } 		$a_80_3 = {73 75 45 4f 71 6a 57 } 		$a_80_4 = {77 44 46 6b 76 } 		$a_80_5 = {7a 45 58 61 75 4f 66 70 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}