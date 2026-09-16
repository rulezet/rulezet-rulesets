rule Trojan_Win32_Qbot_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {52 64 72 66 76 74 4b 6a 68 67 62 79 } 		$a_80_1 = {4f 6a 68 6e 62 67 57 64 63 74 66 76 67 79 62 } 		$a_80_2 = {53 64 72 63 66 74 76 4d 6e 68 67 62 79 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}