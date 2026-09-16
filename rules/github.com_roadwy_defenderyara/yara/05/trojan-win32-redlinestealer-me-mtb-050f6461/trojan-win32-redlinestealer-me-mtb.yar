rule Trojan_Win32_RedLineStealer_ME_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c6 f7 75 08 8a 04 0a 30 04 3e 46 3b 75 0c 72 } 		$a_01_1 = {83 65 9c 00 8b 45 9c 89 45 98 ff 75 98 ff 55 } 		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } 		$a_01_3 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 45 78 57 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}