rule Trojan_BAT_Vidar_A_MTB{
	meta:
		description = "Trojan:BAT/Vidar.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 1d 00 00 01 13 2d 20 00 01 00 00 8d 1d 00 00 01 13 2e 11 04 6e 11 14 6a 30 0c 08 09 5a 13 20 11 2b 11 07 59 13 14 11 21 11 20 31 0a } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}