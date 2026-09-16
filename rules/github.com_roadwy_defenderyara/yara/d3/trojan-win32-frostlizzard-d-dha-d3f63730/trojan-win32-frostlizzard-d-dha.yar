rule Trojan_Win32_FrostLizzard_D_dha{
	meta:
		description = "Trojan:Win32/FrostLizzard.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 8b 4d f0 8b 55 e0 8b 75 c4 66 8b 14 56 66 89 14 41 8b 45 e0 83 c0 01 89 45 e0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}