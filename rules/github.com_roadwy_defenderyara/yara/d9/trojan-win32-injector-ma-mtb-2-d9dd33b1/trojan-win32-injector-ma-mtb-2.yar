rule Trojan_Win32_Injector_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Injector.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 6a 6d 61 6b 66 75 6e 2e 64 6c 6c } 		$a_01_1 = {68 72 79 61 62 77 } 		$a_01_2 = {69 6e 65 68 70 } 		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 } 		$a_01_5 = {57 4e 65 74 41 64 64 43 6f 6e 6e 65 63 74 69 6f 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}