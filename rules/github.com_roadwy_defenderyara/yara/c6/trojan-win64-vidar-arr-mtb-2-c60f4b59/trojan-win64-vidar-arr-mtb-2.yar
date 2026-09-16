rule Trojan_Win64_Vidar_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Vidar.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f be d0 8b ce 0f af cd 8d 04 49 03 d0 } 		$a_01_1 = {8d 04 5a 41 03 c0 33 d2 f7 f1 44 8b c0 0f be 05 } 		$a_03_2 = {0f 57 c0 6b c3 ?? 03 c6 41 03 c0 f7 f1 44 8b c0 0f be 05 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*7+(#a_03_2  & 1)*3) >=20
 
}