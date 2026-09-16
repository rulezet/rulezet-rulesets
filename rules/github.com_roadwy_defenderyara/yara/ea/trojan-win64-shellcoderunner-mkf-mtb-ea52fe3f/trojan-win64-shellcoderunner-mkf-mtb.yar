rule Trojan_Win64_ShellcodeRunner_MKF_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c7 01 48 b8 44 88 41 02 88 41 03 49 8b c0 48 c1 e8 10 88 41 04 49 8b c0 } 	condition:
		((#a_01_0  & 1)*35) >=35
 
}