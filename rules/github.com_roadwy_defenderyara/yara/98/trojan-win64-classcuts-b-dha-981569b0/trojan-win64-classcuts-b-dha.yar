rule Trojan_Win64_ClassCuts_B_dha{
	meta:
		description = "Trojan:Win64/ClassCuts.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 "
		
	strings :
		$a_01_0 = {43 6c 69 65 6e 74 20 72 65 61 64 79 21 } 		$a_01_1 = {47 65 74 54 61 73 6b 73 } 		$a_01_2 = {52 65 73 75 6c 74 73 3d } 		$a_01_3 = {4e 4f 5f 44 41 54 41 } 		$a_01_4 = {53 54 41 54 55 53 5f 4f 4b } 	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100) >=500
 
}