rule Trojan_Win32_Dridex_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 3a 5c 57 6f 72 6b 5c 5f 62 69 6e 5c 52 65 6c 65 61 73 65 2d 57 69 6e 33 32 5c 6c 64 72 2e 70 64 62 } 		$a_80_1 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } 		$a_80_2 = {44 65 62 75 67 42 72 65 61 6b } 	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}