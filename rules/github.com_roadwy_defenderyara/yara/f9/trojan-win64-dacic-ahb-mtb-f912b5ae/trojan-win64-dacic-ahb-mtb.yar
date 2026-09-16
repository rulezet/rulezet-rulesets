rule Trojan_Win64_Dacic_AHB_MTB{
	meta:
		description = "Trojan:Win64/Dacic.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 33 d1 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b c2 48 c1 e0 ?? 48 33 c2 48 33 c1 48 89 43 ?? 0f 31 48 c1 e2 ?? 48 8d 4d 10 48 0b c2 48 33 c1 } 		$a_03_1 = {0f b6 c8 48 8d 46 ?? 8b e9 48 0f 44 de 83 f5 ?? 84 c9 48 0f 44 c6 48 8b 30 44 38 66 19 74 } 		$a_01_2 = {6d 73 65 64 67 65 2e 63 72 61 73 68 70 61 64 5f 25 75 5f 25 30 34 58 } 	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}