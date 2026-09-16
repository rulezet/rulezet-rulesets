rule Trojan_BAT_Redline_MG_MTB{
	meta:
		description = "Trojan:BAT/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 09 16 13 0a 2b 22 11 09 11 0a 9a 13 0b 00 06 11 0b 6f ?? ?? ?? 06 13 0c 11 0c 2c 05 00 17 0d 2b 0f 00 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d6 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}