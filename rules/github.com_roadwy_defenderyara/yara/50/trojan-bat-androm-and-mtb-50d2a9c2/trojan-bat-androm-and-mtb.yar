rule Trojan_BAT_Androm_AND_MTB{
	meta:
		description = "Trojan:BAT/Androm.AND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 02 03 59 11 03 59 20 ff 00 00 00 5f d2 13 02 20 05 00 00 00 7e 16 00 00 04 7b 29 00 00 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}