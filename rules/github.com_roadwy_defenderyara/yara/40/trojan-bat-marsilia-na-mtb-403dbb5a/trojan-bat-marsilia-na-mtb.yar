rule Trojan_BAT_Marsilia_NA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 07 11 07 2c 0c 00 11 05 1a 5a 11 06 58 13 04 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}