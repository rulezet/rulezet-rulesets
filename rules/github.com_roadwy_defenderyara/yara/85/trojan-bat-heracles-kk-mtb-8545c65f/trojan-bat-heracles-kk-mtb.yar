rule Trojan_BAT_Heracles_KK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 00 70 28 a0 00 00 0a 26 02 28 11 00 00 0a 0a 28 9a 00 00 0a 06 16 06 8e 69 6f 9b 00 00 0a 2a } 		$a_01_1 = {6f 8c 00 00 0a 16 26 26 18 8d 1d 00 00 01 25 16 17 9c 25 17 18 9c 2a } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}