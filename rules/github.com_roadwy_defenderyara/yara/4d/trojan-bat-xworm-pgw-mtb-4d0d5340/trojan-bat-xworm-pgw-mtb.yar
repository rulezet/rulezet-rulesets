rule Trojan_BAT_Xworm_PGW_MTB{
	meta:
		description = "Trojan:BAT/Xworm.PGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 16 fe 01 13 05 11 05 2c 0f 02 11 04 02 11 04 91 20 ?? 00 00 00 61 b4 9c 11 04 17 d6 13 04 11 04 09 31 d9 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}