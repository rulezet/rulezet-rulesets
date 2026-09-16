rule Trojan_Win32_EyeStye_H{
	meta:
		description = "Trojan:Win32/EyeStye.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {5f 54 45 4e 59 50 53 5f 5f } 		$a_02_1 = {6c 6d 78 2e [0-08] 2d 73 65 69 6b 6f 6f 63 } 		$a_00_2 = {45 4d 41 4e 54 4f 42 25 } 		$a_02_3 = {1b 6a 00 43 dc fe 04 dc fe 04 0c ff 0a 08 00 08 00 04 b0 fe 04 0c ff fd fe ?? fe 04 3c ff fd fe ?? fe 07 08 00 80 00 24 0a 00 0d 20 00 0b 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}