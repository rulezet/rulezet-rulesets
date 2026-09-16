rule Trojan_Win64_ShellcodeRunner_RP_MTB_2{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 c9 48 c7 c2 ?? ?? 00 00 41 b8 00 10 00 00 44 8d 49 40 48 ff 15 ?? ?? ?? ?? e8 00 00 00 00 5e 48 81 c6 ?? ?? ?? ?? 48 89 c7 48 c7 ?? ?? ?? ?? 00 48 89 c2 90 90 a4 90 90 e2 fb ff e2 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}