rule Trojan_Win32_Foosace_C_dha{
	meta:
		description = "Trojan:Win32/Foosace.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 } 		$a_01_1 = {25 73 2f 63 67 69 2d 62 69 6e 2f 25 73 2e 63 67 69 3f 25 73 00 } 		$a_01_2 = {69 6e 73 3a 25 2e 38 78 00 } 		$a_01_3 = {49 6e 69 74 31 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}