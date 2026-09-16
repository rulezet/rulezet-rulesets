rule Trojan_Win32_BlackMoon_GNT_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {2a 43 5d 44 0a 53 ?? 67 00 25 3c 0b 83 37 ?? 59 b0 00 8c 1c c7 36 b7 92 04 68 01 27 } 		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 45 6e 63 72 79 70 74 53 79 6e 61 70 74 69 63 73 2e 63 6f 6d } 		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}