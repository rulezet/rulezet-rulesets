rule Trojan_Win32_Emotet_RTH_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7a 5a 24 62 65 28 33 62 52 3e 78 67 25 69 6c 37 4d 72 3e 75 6a 75 6d 4e 38 64 24 65 75 24 6a 39 58 5e 32 40 4b 70 6a 2b 34 33 42 77 62 53 41 30 26 61 4d 65 6b 28 7a 75 42 4a 26 45 29 23 5a 78 6c 66 33 31 4d 28 5a 39 4f 47 3f 6d 32 3e 49 4e 39 73 77 62 68 53 74 26 78 6c 5e } 		$a_03_1 = {83 c2 01 89 55 ?? 8b ?? ?? 3b ?? ?? 73 [0-12] 03 [0-05] 8a 02 88 01 eb } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}