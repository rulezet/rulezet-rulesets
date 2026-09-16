rule Trojan_Win32_Emotet_RF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {61 72 7a 74 6f 65 6c 61 6f 67 68 77 75 71 67 } 		$a_81_1 = {62 76 61 77 6e 6c 66 6d 71 64 71 67 67 76 72 69 } 		$a_81_2 = {64 78 62 6a 71 71 7a 76 67 77 65 79 78 69 62 7a } 		$a_81_3 = {67 67 70 74 6c 68 67 6b 76 64 64 70 79 70 71 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}