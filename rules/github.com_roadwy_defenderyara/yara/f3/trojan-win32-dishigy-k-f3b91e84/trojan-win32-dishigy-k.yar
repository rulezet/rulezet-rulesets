rule Trojan_Win32_Dishigy_K{
	meta:
		description = "Trojan:Win32/Dishigy.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } 		$a_03_1 = {bf 01 00 00 00 8b 45 ?? 90 17 03 06 05 05 33 db 8a 5c 38 ff 0f b6 5c 38 ff 0f b7 5c 78 fe 33 5d ?? 3b 5d ?? 7f 0b 81 c3 ff 00 00 00 } 		$a_00_2 = {71 00 75 00 69 00 6e 00 61 00 73 00 20 00 56 00 69 00 72 00 74 00 75 00 61 00 69 00 73 00 2e 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}