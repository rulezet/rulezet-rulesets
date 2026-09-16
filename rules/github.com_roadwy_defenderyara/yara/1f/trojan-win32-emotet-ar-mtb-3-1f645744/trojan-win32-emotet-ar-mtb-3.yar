rule Trojan_Win32_Emotet_AR_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_80_0 = {71 65 70 66 6a 61 6e 63 69 6b 70 6b } 		$a_80_1 = {6c 77 63 69 6b 6d 69 6c 74 67 6a 6a 76 6c 73 } 		$a_80_2 = {69 63 73 6e 62 67 73 68 61 76 62 71 70 64 } 		$a_80_3 = {6e 62 6a 64 68 6d 72 6c 6e 6e 61 74 76 65 6f 6f } 		$a_80_4 = {65 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*10) >=12
 
}