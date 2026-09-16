rule Trojan_Win64_ShellcodeRunner_ARR_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b c3 49 f7 e1 49 ff c1 48 c1 ea ?? 48 ?? ?? ?? 48 2b c8 [0-05] 43 32 04 ?? 41 88 00 4c 3b ce } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}