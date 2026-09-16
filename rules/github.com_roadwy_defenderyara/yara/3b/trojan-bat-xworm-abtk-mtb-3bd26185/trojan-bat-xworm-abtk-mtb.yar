rule Trojan_BAT_XWorm_ABTK_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ABTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 16 16 6f ?? 00 00 0a 13 06 11 04 17 16 6f ?? 00 00 0a 13 07 11 05 16 12 06 28 ?? 00 00 0a 9c 11 05 17 12 06 28 ?? 00 00 0a 9c 11 05 18 12 06 28 ?? 00 00 0a 9c 11 05 19 12 07 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}