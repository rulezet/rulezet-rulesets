rule Trojan_Win32_Dridex_AR_MTB_5{
	meta:
		description = "Trojan:Win32/Dridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_02_0 = {2b ca 88 4d d7 b8 02 00 00 00 6b c8 09 0f b7 91 ?? ?? ?? ?? b8 02 00 00 00 6b c8 06 0f b7 81 } 		$a_80_1 = {53 6f 6c 75 74 69 6f 6e 5f 6f 6e 65 5c 75 73 65 2e 70 64 62 } 		$a_80_2 = {43 6f 6d 70 6c 65 74 65 62 65 67 61 6e } 		$a_80_3 = {53 65 61 72 63 68 6e 65 69 67 68 62 6f 72 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}