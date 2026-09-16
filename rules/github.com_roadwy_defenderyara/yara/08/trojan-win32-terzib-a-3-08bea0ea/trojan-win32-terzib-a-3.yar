rule Trojan_Win32_Terzib_A_3{
	meta:
		description = "Trojan:Win32/Terzib.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 45 4c 20 2f 51 20 2f 53 20 22 25 73 5c 68 69 73 74 6f 72 79 } 		$a_01_1 = {43 6f 6f 6b 69 65 3a 20 2f 73 65 61 72 63 68 3f 68 6c 3d 65 6e 3d 71 3d } 		$a_03_2 = {c7 01 ff 55 55 ff 8b 95 24 f9 ff ff c7 42 04 00 00 00 00 8b 85 24 f9 ff ff c6 40 08 00 81 7d c0 00 60 00 00 7d 18 8b 8d 24 f9 ff ff 66 c7 41 0e ff ff c7 ?? ?? ?? ?? 00 01 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}