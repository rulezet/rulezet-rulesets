rule Trojan_Win32_Ghodow_A{
	meta:
		description = "Trojan:Win32/Ghodow.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 7d ec 02 76 19 89 0f 85 } 		$a_01_1 = {80 39 8b 75 06 80 79 01 35 74 09 41 42 83 fa 64 7c ee eb 03 } 		$a_03_2 = {cd 2a 8d 15 ?? ?? ?? ?? cd ee eb 13 68 f4 01 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}