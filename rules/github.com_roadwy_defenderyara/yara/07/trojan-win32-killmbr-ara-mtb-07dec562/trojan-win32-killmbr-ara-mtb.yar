rule Trojan_Win32_KillMBR_ARA_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 99 f7 fe 8a f8 8b c1 99 8a df f7 ff 8b 45 ec fe cb 02 55 e4 41 32 d3 0a d7 8b 5d e0 88 10 83 c0 04 89 45 ec 3b cb 7c d6 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}