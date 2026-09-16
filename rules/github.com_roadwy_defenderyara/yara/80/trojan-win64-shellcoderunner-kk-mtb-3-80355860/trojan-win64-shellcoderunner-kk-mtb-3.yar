rule Trojan_Win64_ShellcodeRunner_KK_MTB_3{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {d1 e8 89 c2 8b 45 ?? 83 e0 01 f7 d8 25 78 3b f6 82 31 d0 89 45 ?? 83 45 ?? 01 } 		$a_03_1 = {48 b8 6b 65 72 6e 65 6c 33 32 48 89 45 ?? 48 b8 6c 33 32 2e 64 6c 6c 00 48 89 45 ?? 48 b8 4b 45 52 4e 45 4c 33 32 48 89 45 ?? 48 b8 4c 33 32 2e 44 4c 4c 00 48 89 45 } 	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}