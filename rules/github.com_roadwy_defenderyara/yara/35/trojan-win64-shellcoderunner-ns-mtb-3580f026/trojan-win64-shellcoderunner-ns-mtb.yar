rule Trojan_Win64_ShellCodeRunner_NS_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {65 4d 8b 36 4d 8b 36 48 8d 05 ?? ?? 06 00 48 89 04 24 e8 34 71 02 00 45 0f 57 ff 4c 8b 35 } 		$a_03_1 = {bb 00 00 01 00 0f 1f 00 e8 5b 95 04 00 eb 8d 48 89 7c 24 ?? b8 00 00 01 00 31 db } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}