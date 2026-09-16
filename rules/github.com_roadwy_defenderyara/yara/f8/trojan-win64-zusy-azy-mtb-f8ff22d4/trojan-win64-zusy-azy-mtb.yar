rule Trojan_Win64_Zusy_AZY_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 8b c0 48 8d 95 ?? ?? ?? ?? 48 8d 4d 80 e8 ?? ?? ?? ?? 4c 8d 4c 24 78 41 b8 00 08 00 00 48 8d 95 ?? ?? ?? ?? 48 8b cb ff 15 } 		$a_01_1 = {4c 89 74 24 28 c7 44 24 20 00 00 00 80 45 33 c9 45 33 c0 48 8b d0 48 8b ce ff 15 } 		$a_01_2 = {6c 6f 67 6e 61 74 69 6f 6e 70 72 69 6d 65 63 61 72 72 61 72 6f 2e 63 6f 6d 2f 73 65 74 74 69 6e 67 73 2f 63 6f 6e 66 69 67 32 2e 7a 69 70 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=6
 
}