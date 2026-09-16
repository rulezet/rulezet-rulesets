rule Trojan_BAT_XWorm_AWM_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.AWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 06 28 ?? 00 00 0a 11 0a 20 80 00 00 00 28 ?? 00 00 0a 73 ?? 00 00 0a 13 0b 11 0b 11 0a 6f ?? 00 00 0a 11 0b 17 6f ?? 00 00 0a 11 0b 11 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 11 0b 16 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}