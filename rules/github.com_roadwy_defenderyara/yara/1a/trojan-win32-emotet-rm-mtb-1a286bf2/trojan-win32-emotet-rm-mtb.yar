rule Trojan_Win32_Emotet_RM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {48 63 66 79 76 67 4f 68 62 76 67 } 		$a_80_1 = {59 79 76 67 4b 62 75 76 67 79 } 		$a_80_2 = {57 78 64 74 63 66 76 67 4f 6e 6a 6b 68 62 6a 67 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}