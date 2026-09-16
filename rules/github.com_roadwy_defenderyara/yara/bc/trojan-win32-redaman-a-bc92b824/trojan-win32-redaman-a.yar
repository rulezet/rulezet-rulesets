rule Trojan_Win32_Redaman_A{
	meta:
		description = "Trojan:Win32/Redaman.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 72 69 74 65 50 72 6f 5f 5f 5f 5f 5f 65 5f 6f 72 79 } 		$a_01_1 = {72 5f 61 5f 4c 69 62 72 61 72 79 41 } 		$a_03_2 = {85 d2 74 2d 31 c9 2b 0e f7 d9 83 ee ?? 4e f7 d1 83 e9 ?? 01 d9 83 c1 ?? 49 89 cb 89 0f 83 c7 ?? 83 ea ?? 8d 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? ff e1 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}