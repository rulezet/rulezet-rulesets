rule Trojan_Win32_FrostLizzard_D_dha_2{
	meta:
		description = "Trojan:Win32/FrostLizzard.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 14 24 8b 55 3c 01 ea 8b 4c ca 78 8b 5c 0d 20 01 eb 8b 54 0d 1c 89 54 24 08 8b 4c 0d 24 89 4c 24 10 31 d2 90 90 90 90 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}