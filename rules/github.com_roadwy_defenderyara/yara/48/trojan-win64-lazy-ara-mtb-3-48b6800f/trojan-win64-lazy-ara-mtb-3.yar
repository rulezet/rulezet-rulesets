rule Trojan_Win64_Lazy_ARA_MTB_3{
	meta:
		description = "Trojan:Win64/Lazy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 50 50 4c 4b 69 6c 6c 65 72 2e 70 64 62 } 		$a_80_1 = {5c 54 65 6d 70 5c 52 54 43 6f 72 65 36 34 2e 73 79 73 } 		$a_80_2 = {64 69 73 61 62 6c 65 50 50 4c } 		$a_80_3 = {64 69 73 61 62 6c 65 4c 53 41 50 72 6f 74 65 63 74 69 6f 6e } 	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=6
 
}