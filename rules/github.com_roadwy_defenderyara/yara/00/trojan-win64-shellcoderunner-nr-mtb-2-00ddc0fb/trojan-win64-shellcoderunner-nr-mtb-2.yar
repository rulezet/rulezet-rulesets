rule Trojan_Win64_ShellcodeRunner_NR_MTB_2{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 44 24 ?? 48 8b 4a 08 45 33 c9 48 c7 44 24 ?? 00 00 00 00 ba 00 00 00 10 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 } 		$a_03_1 = {48 89 5c 24 ?? 33 d2 48 8b c8 48 89 7c 24 70 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}