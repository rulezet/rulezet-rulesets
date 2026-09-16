rule Trojan_BAT_Xworm_PGW_MTB_2{
	meta:
		description = "Trojan:BAT/Xworm.PGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 fe 06 38 00 00 06 73 ?? 00 00 0a 0a 06 14 73 ?? 00 00 0a 20 10 27 00 00 20 98 3a 00 00 6f ?? 00 00 0a 73 ?? 00 00 0a 20 10 27 00 00 20 98 3a 00 00 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}