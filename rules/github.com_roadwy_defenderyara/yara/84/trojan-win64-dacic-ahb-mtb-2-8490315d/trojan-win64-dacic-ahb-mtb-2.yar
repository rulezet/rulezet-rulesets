rule Trojan_Win64_Dacic_AHB_MTB_2{
	meta:
		description = "Trojan:Win64/Dacic.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 33 d1 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b c2 48 c1 e0 ?? 48 33 c2 48 33 c1 48 89 43 ?? 0f 31 48 c1 e2 ?? 48 8d 4d 10 48 0b c2 48 33 c1 } 		$a_01_1 = {57 41 52 4e 49 4e 47 3a 20 41 6e 61 6c 79 73 69 73 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 64 65 74 65 63 74 65 64 } 		$a_01_2 = {4f 62 66 75 73 63 61 74 69 6f 6e 20 6d 61 79 20 62 65 20 63 6f 6d 70 72 6f 6d 69 73 65 64 } 	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}