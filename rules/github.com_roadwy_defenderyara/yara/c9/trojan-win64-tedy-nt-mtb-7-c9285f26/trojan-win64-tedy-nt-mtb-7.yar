rule Trojan_Win64_Tedy_NT_MTB_7{
	meta:
		description = "Trojan:Win64/Tedy.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 12 45 33 c0 41 8d 50 ?? 33 c9 48 8b 03 ff 15 d1 2f 00 00 e8 f8 06 00 00 48 8b d8 48 83 38 ?? 74 14 48 8b c8 } 		$a_01_1 = {46 69 78 20 46 61 6b 65 20 44 61 6d 61 67 65 } 		$a_01_2 = {43 41 52 4c 4f 53 20 43 48 45 41 54 } 		$a_01_3 = {41 41 52 59 41 4e 20 56 34 58 20 2d 20 53 6e 69 70 65 72 20 50 61 6e 65 6c } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}