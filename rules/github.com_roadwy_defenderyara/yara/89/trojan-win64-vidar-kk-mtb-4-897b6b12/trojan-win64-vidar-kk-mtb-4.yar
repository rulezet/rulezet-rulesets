rule Trojan_Win64_Vidar_KK_MTB_4{
	meta:
		description = "Trojan:Win64/Vidar.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8d 1c 02 48 8b b4 24 ?? 00 00 00 48 01 d6 0f b6 36 40 88 33 48 ff c2 } 		$a_03_1 = {8b 71 04 48 8b 7c 24 ?? 48 8d 1c 37 48 8b 84 24 ?? 00 00 00 48 8b 8c 24 ?? 00 00 00 48 8b 54 24 } 		$a_01_2 = {6d 61 69 6e 2e 47 65 74 49 6e 73 74 61 6c 6c 44 65 74 61 69 6c 73 50 61 79 6c 6f 61 64 } 	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}