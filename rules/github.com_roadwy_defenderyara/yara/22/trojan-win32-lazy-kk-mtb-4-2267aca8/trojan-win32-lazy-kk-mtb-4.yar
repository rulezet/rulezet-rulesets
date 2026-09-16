rule Trojan_Win32_Lazy_KK_MTB_4{
	meta:
		description = "Trojan:Win32/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 57 6a 00 6a 00 6a 00 68 00 00 00 80 6a 00 68 00 00 00 80 68 00 00 cf 00 68 a0 74 ?? 00 68 d8 73 ?? 00 6a 00 ff } 		$a_03_1 = {8b 4d bc 8b 14 8d 28 71 ?? 00 03 55 b4 8a 0c 03 03 d3 43 88 4c 32 2e 3b df } 		$a_01_2 = {46 61 6b 65 43 68 72 6f 6d 65 5c 52 65 6c 65 61 73 65 5c 43 68 72 6f 6d 65 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}