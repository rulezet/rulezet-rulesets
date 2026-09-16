rule Trojan_BAT_Jalapeno_EAJF_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.EAJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 28 28 00 00 0a 07 6f 29 00 00 0a 1e 5b 8d 3e 00 00 01 13 04 1e 11 04 16 1e 28 2a 00 00 0a 73 2b 00 00 0a 13 05 04 07 08 11 04 6f 2c 00 00 0a 16 73 2d 00 00 0a 13 06 11 06 11 05 28 39 01 00 06 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}