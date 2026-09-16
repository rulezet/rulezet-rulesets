rule Trojan_Win64_Aotera_KK_MTB{
	meta:
		description = "Trojan:Win64/Aotera.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b d1 41 8b 54 96 10 43 89 54 8e 10 8b d1 45 89 5c 96 10 41 ff c1 41 81 f9 00 01 00 00 } 		$a_01_1 = {41 8b c3 41 0f b6 44 86 10 33 d0 41 8b c1 88 54 01 10 41 ff c1 41 3b f9 } 		$a_01_2 = {41 c1 e7 04 41 0b c7 42 88 44 37 10 83 c5 02 41 ff c6 3b ee 7c c0 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}