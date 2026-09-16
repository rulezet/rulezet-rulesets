rule Trojan_BAT_Bladabindi_EB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {06 1e 58 4a 93 11 04 33 0e 06 06 4a 1f 3a 5a 06 1e 58 4a 58 54 2b 12 06 1e 58 06 1e 58 4a 17 58 54 06 1e 58 4a 1f 3a 32 d2 06 1a 58 06 1a 58 4a 17 59 54 16 3a 9d 00 00 00 06 1a 58 4a 16 2f 9a } 		$a_81_1 = {5a 53 44 52 54 47 48 55 4a 4b 4c 4f 49 4b 4a 48 47 46 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3) >=13
 
}