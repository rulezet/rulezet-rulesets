rule Trojan_BAT_Marsilia_AMR_MTB_2{
	meta:
		description = "Trojan:BAT/Marsilia.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 3b 11 07 11 08 9a 13 09 11 05 11 09 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 58 13 05 11 06 11 09 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 06 11 08 17 58 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}