rule Trojan_Win32_ShellcodeRunner_ARR_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 c2 41 32 c0 0f b6 c8 41 f6 c3 ?? 41 0f b6 c2 41 0f 44 c8 02 c0 } 		$a_01_1 = {48 ff c0 32 4a f0 88 0a 48 83 f8 } 	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*12) >=20
 
}