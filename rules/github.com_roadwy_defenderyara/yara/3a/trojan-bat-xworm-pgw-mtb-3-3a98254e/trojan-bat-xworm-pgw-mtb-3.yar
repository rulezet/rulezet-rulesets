rule Trojan_BAT_Xworm_PGW_MTB_3{
	meta:
		description = "Trojan:BAT/Xworm.PGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 1f 16 94 13 23 11 1f 17 94 13 24 02 11 23 11 24 6f ?? 00 00 0a 13 25 0e 0b 2c 39 11 1b 18 31 34 } 		$a_01_1 = {11 27 06 61 06 61 d2 13 27 11 28 16 61 d2 13 28 11 29 06 61 06 61 d2 13 29 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}