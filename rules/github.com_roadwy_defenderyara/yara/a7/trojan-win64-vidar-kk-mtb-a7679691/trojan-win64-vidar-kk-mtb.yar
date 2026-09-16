rule Trojan_Win64_Vidar_KK_MTB{
	meta:
		description = "Trojan:Win64/Vidar.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 21 06 00 eb 54 00 00 18 55 00 00 68 21 06 00 } 		$a_01_1 = {21 57 00 00 90 21 06 00 21 57 00 00 33 57 00 00 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}