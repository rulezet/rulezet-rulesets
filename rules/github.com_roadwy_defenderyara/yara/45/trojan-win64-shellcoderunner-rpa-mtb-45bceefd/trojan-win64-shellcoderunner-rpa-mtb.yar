rule Trojan_Win64_ShellcodeRunner_RPA_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 45 f0 49 89 c1 48 8d 45 f8 49 89 c0 48 b8 7e 13 00 00 00 00 00 00 49 89 c3 48 8d 05 3c 13 00 00 49 89 c2 4c 89 d1 4c 89 da } 		$a_01_1 = {b8 00 30 00 00 48 89 44 24 20 48 8d 45 d8 49 89 c1 48 b8 00 00 00 00 00 00 00 00 49 89 c0 48 8d 45 e0 49 89 c3 48 8b 45 e8 49 89 c2 4c 89 d1 4c 89 da 4c 8b 1d 04 80 03 00 41 ff d3 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}