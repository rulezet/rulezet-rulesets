rule Trojan_Win32_Amadey_AMD_MTB_5{
	meta:
		description = "Trojan:Win32/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 8d 47 34 50 8b 44 24 24 8b 80 a4 00 00 00 83 c0 08 50 ff 74 24 30 ff 15 ?? ?? ?? ?? 8b 4c 24 18 8b 47 28 03 44 24 14 51 } 		$a_01_1 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d e0 5c 46 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 e0 5c 46 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}