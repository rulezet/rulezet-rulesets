rule Trojan_BAT_Amadey_AMA_MTB_2{
	meta:
		description = "Trojan:BAT/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 2c eb 73 ?? 00 00 0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 16 06 8e 69 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}