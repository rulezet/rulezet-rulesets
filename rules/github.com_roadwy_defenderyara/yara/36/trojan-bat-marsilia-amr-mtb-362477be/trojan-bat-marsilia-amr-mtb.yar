rule Trojan_BAT_Marsilia_AMR_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 1f 10 0b 07 28 ?? 00 00 06 68 0c 08 20 00 80 00 00 5f 20 00 80 00 00 fe 01 13 05 11 05 2c 04 00 17 0a 00 28 ?? 00 00 0a 0d 06 09 60 13 04 11 04 13 06 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}