rule Trojan_BAT_Zusy_BAD_MTB{
	meta:
		description = "Trojan:BAT/Zusy.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 20 04 00 00 00 38 b5 ff ff ff 11 01 16 ?? ?? 00 00 0a 13 02 38 00 00 00 00 11 00 16 73 05 00 00 0a 13 09 20 01 00 00 00 7e 58 00 00 04 7b 48 00 00 04 39 88 ff ff ff 26 20 02 00 00 00 38 7d ff ff ff 00 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}