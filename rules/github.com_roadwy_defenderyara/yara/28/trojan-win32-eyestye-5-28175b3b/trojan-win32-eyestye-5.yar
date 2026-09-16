rule Trojan_Win32_EyeStye_5{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {b8 07 63 f5 53 66 c7 44 24 ?? bf b6 } 		$a_01_1 = {7f d5 c6 44 3e fe 0d c6 44 3e ff 0a c6 04 3e 00 } 		$a_01_2 = {2a 66 6f 72 75 6d 2a 6e 65 77 72 65 70 6c 79 2e 70 68 70 2a } 		$a_01_3 = {73 70 79 53 70 72 65 61 64 2e 64 6c 6c 00 43 61 6c 6c } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=3
 
}