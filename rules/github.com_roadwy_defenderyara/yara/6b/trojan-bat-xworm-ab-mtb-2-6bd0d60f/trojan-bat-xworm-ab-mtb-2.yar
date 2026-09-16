rule Trojan_BAT_XWorm_AB_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 11 05 6f ?? 00 00 0a 13 06 03 09 6f ?? 00 00 0a 59 13 07 09 17 8d 80 00 00 01 25 16 12 06 28 77 00 00 0a 9c 6f ?? 00 00 0a 00 11 07 17 59 25 13 07 16 fe 02 16 fe 01 13 10 11 10 2c 05 38 ee 00 00 00 09 17 8d 80 00 00 01 25 16 12 06 28 ?? 00 00 0a 9c } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}