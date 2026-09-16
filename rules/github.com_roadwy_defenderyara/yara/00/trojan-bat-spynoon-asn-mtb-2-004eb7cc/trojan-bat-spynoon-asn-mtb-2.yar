rule Trojan_BAT_SpyNoon_ASN_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 3d 17 13 08 16 13 09 2b 17 06 09 11 09 58 91 07 11 09 91 2e 05 16 13 08 2b 0d 11 09 17 58 13 09 11 09 07 8e 69 32 e2 11 08 2c 0f 08 09 6f ?? 00 00 0a 09 07 8e 69 58 0d 2b 04 09 17 58 0d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}