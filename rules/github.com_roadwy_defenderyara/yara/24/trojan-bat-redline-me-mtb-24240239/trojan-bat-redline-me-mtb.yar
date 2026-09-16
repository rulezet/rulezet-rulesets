rule Trojan_BAT_RedLine_ME_MTB{
	meta:
		description = "Trojan:BAT/RedLine.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 22 09 11 04 9a 13 05 06 11 05 6f ?? ?? ?? 06 2c 0c 06 6f ?? ?? ?? 06 2c 04 17 0b 2b 0d 11 04 17 58 13 04 11 04 09 8e 69 32 d7 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}