rule Trojan_Win64_ShellcodeRunner_KK_MTB_2{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 85 70 20 00 00 48 8d 50 01 48 89 95 70 20 00 00 8b 95 7c 20 00 00 8d 4a 01 89 8d 7c 20 00 00 0f b6 08 48 63 c2 88 4c 05 d0 } 		$a_01_1 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 8d 48 fb 8b 45 fc 48 63 d0 48 8b 45 f0 48 01 d0 89 ca 88 10 83 45 fc 01 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}