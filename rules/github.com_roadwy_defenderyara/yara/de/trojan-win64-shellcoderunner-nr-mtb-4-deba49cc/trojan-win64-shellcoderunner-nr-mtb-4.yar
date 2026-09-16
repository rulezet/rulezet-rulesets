rule Trojan_Win64_ShellcodeRunner_NR_MTB_4{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 45 d0 41 b9 ?? 00 00 00 49 89 d0 ba ?? ?? 00 00 48 89 c1 e8 ?? ?? ff ff 48 8b 85 ?? ?? 00 00 48 8d 15 ?? ?? 00 00 48 89 c1 48 8b 05 } 		$a_03_1 = {ff d0 48 89 85 ?? ?? 00 00 4c 8b 95 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 c7 44 24 ?? ?? 00 00 00 41 b9 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}