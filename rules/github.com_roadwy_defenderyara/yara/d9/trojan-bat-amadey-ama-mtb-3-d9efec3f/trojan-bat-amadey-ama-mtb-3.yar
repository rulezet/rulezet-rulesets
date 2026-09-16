rule Trojan_BAT_Amadey_AMA_MTB_3{
	meta:
		description = "Trojan:BAT/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 13 05 08 20 0b 01 00 00 33 0d 11 05 20 98 00 00 00 58 68 13 05 2b 0b 11 05 20 a8 00 00 00 58 68 13 05 06 11 05 6a 16 6f ?? 00 00 0a 26 11 04 06 6f ?? 00 00 0a 69 6f ?? 00 00 0a 11 04 02 7b 1a 00 00 04 6f } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}