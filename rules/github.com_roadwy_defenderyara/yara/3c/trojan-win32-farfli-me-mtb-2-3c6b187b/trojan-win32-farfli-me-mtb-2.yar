rule Trojan_Win32_Farfli_ME_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 8b 7c 24 0c 33 c9 85 ff 7e ?? 53 56 8b 74 24 10 8b c1 bb 03 00 00 00 99 f7 fb 8a 04 31 83 fa 01 75 ?? 3c 20 7e ?? 3c 7f 7d ?? fe c8 eb ?? 3c 20 7e ?? 3c 7f 7d ?? fe c0 88 04 31 41 3b cf 7c } 		$a_03_1 = {b9 41 00 00 00 33 c0 8d 7c 24 64 8d 54 24 64 f3 ab bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 2b f9 c7 44 24 60 00 00 00 00 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 8d 7c 24 64 83 c9 ff f2 ae f7 d1 49 51 8d 4c 24 68 51 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}