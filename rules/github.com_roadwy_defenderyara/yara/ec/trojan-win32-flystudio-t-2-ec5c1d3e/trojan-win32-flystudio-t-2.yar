rule Trojan_Win32_FlyStudio_T_2{
	meta:
		description = "Trojan:Win32/FlyStudio.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 02 00 00 80 6a 00 68 00 00 00 00 68 04 00 00 80 6a 00 68 ?? ?? ?? 00 68 03 00 00 00 bb ?? ?? ?? 00 e8 } 		$a_03_1 = {68 04 00 00 80 6a 00 68 ?? ?? ?? 00 68 01 00 00 00 b8 01 00 00 00 bb ?? ?? ?? 00 e8 } 		$a_02_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 31 31 31 6d 2e 69 6e 66 6f 2f 76 69 70 2f 76 69 70 ?? 2e 6a 70 67 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}