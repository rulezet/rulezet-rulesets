rule Trojan_Win64_Tedy_NT_MTB_8{
	meta:
		description = "Trojan:Win64/Tedy.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6f 4c 24 ?? 48 8d 54 24 ?? 48 8d 0d 97 68 02 00 48 89 74 24 ?? 48 89 74 24 ?? 0f 29 4c 24 ?? e8 33 75 00 00 0f b6 33 4c 89 e1 c6 03 00 } 		$a_01_1 = {80 3b 00 75 11 40 88 33 40 84 f6 75 09 4c 89 e9 e8 bf 75 00 00 } 		$a_01_2 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 72 65 6e 61 6d 65 20 66 69 6c 65 20 6e 61 6d 65 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}