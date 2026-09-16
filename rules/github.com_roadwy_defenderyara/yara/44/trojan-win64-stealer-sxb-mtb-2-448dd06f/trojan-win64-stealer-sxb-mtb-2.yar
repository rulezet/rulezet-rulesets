rule Trojan_Win64_Stealer_SXB_MTB_2{
	meta:
		description = "Trojan:Win64/Stealer.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 8d 44 24 48 49 83 fe ?? 49 0f 47 c3 42 0f b7 0c 40 8d 41 d0 66 83 f8 ?? 76 17 8d 41 bf 66 83 f8 ?? 76 0e 66 83 e9 ?? 66 83 f9 ?? 0f 87 ?? ?? ?? ?? 49 ff c0 4c 3b c2 72 c6 } 		$a_01_1 = {55 53 44 54 20 68 69 6a 61 63 6b } 		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } 		$a_01_3 = {47 65 74 4b 65 79 53 74 61 74 65 } 		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}