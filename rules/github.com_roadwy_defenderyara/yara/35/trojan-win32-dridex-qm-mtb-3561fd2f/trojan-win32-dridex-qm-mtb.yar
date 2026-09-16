rule Trojan_Win32_Dridex_QM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 05 00 00 "
		
	strings :
		$a_00_0 = {8b c1 2b c6 83 c0 21 2b f1 8d 04 41 } 		$a_00_1 = {8b ce 2b ca 8b d6 81 e9 35 f8 00 00 } 		$a_80_2 = {6d 69 6c 65 5c 4c 69 6e 65 2e 70 64 62 } 		$a_80_3 = {42 6c 6f 6f 64 62 72 6f 61 64 } 		$a_80_4 = {52 6f 63 6b 6c 69 6e 65 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=29
 
}