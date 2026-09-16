rule Trojan_Win64_ShellcodeRunner_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8a 04 13 41 80 f0 ?? 44 88 04 01 48 ff c0 48 ff c2 48 39 d7 } 		$a_03_1 = {48 ff c7 48 33 ce e8 ?? ?? ?? ?? ?? ?? ?? 49 0f af f5 48 ff cb } 	condition:
		((#a_03_0  & 1)*8+(#a_03_1  & 1)*12) >=20
 
}