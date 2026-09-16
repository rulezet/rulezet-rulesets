rule Trojan_Win64_ShellCodeRunner_NS_MTB_2{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b e8 45 33 c0 48 85 ed 74 4e 43 0f b7 34 44 49 3b f1 75 37 47 8b 5c 85 00 4d 03 da 33 ff eb 16 8b d7 8b c7 c1 e0 19 d3 ea } 		$a_01_1 = {45 84 ff 75 e2 3b 7c 24 40 75 07 41 8b 1c b6 49 03 da 49 ff c0 4c 3b c5 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}