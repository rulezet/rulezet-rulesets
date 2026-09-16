rule Trojan_BAT_Netwire_AN_MTB{
	meta:
		description = "Trojan:BAT/Netwire.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 09 11 0a 6f ?? 00 00 0a 13 0b 2b 19 11 0a 11 09 6f ?? 00 00 0a 0d 08 09 28 ?? 00 00 0a d6 0c 11 09 17 d6 13 09 11 09 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}