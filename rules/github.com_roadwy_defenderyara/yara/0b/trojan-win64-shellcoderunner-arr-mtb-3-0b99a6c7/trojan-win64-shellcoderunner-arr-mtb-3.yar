rule Trojan_Win64_ShellcodeRunner_ARR_MTB_3{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 65 63 74 53 68 65 6c 6c 63 6f 64 65 52 65 6d 6f 74 65 50 72 6f 63 65 73 73 20 66 61 69 6c 65 64 3a 20 25 64 } 		$a_01_1 = {53 68 65 6c 6c 63 6f 64 65 20 64 65 63 72 79 70 74 65 64 20 61 6e 64 20 77 72 69 74 74 65 6e 20 74 6f 20 30 78 25 70 } 		$a_01_2 = {4d 6f 64 33 33 2d 50 72 6f 63 45 6e 75 6d 53 68 65 6c 6c 63 6f 64 65 49 6e 6a 65 63 74 69 6f 6e 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*6+(#a_01_2  & 1)*4) >=20
 
}