rule Trojan_Win32_Dridex_DK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {8a 5d fb 32 5d fb 88 5d fb 89 45 ec } 		$a_80_1 = {44 6f 6f 72 72 6c 65 64 46 67 70 70 72 } 		$a_80_2 = {47 70 65 72 6e 66 65 64 65 65 66 65 2e 70 64 62 } 		$a_80_3 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } 	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}