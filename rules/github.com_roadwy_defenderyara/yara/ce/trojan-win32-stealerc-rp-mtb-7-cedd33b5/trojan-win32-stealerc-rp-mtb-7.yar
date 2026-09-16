rule Trojan_Win32_Stealerc_RP_MTB_7{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 61 6a 69 70 69 78 75 6b 75 6a 75 6a 65 76 6f 6d 69 72 61 67 69 76 69 6c 75 70 } 		$a_01_1 = {73 6f 74 61 78 6f 6e 6f 76 69 67 61 7a 6f } 		$a_01_2 = {58 69 79 75 66 } 		$a_01_3 = {62 65 73 6f 68 61 6b 65 78 75 78 61 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}