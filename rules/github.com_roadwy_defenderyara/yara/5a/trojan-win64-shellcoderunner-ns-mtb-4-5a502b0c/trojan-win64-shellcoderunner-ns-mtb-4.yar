rule Trojan_Win64_ShellCodeRunner_NS_MTB_4{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 32 f6 40 88 74 24 ?? e8 fe 03 00 00 8a d8 8b 0d 96 1a 02 00 83 f9 01 0f 84 23 01 00 00 85 c9 75 4a c7 05 7f 1a 02 00 ?? ?? ?? ?? 48 8d 15 e8 59 01 00 48 8d 0d a9 59 01 00 } 		$a_03_1 = {48 8d 05 d2 13 02 00 89 74 24 68 48 89 45 80 48 8d 05 b3 13 02 00 48 89 45 88 c7 44 24 78 ?? ?? ?? ?? e8 a2 f9 ff ff } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}