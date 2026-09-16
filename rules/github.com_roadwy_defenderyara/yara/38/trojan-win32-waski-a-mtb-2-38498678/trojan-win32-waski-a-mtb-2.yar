rule Trojan_Win32_Waski_A_MTB_2{
	meta:
		description = "Trojan:Win32/Waski.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c } 		$a_00_1 = {8b 4d e8 8b 41 3c ff 75 f0 03 c1 0f b7 50 06 6b d2 28 8d 84 02 d0 00 00 00 8b 70 14 03 70 10 03 f1 } 		$a_00_2 = {31 0c 96 8b 45 f8 42 c1 e8 02 } 		$a_01_3 = {62 00 75 00 64 00 68 00 61 00 2e 00 65 00 78 00 65 00 } 		$a_01_4 = {6b 00 69 00 6c 00 66 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}