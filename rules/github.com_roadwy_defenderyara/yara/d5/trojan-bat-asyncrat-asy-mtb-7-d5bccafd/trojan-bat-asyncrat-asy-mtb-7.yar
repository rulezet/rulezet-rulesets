rule Trojan_BAT_AsyncRat_ASY_MTB_7{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 da 0d 16 13 04 2b 36 11 04 1f 30 5d 16 fe 01 13 05 11 05 2c 15 08 07 11 04 91 20 ff 00 00 00 61 b4 6f ?? 00 00 0a 00 00 2b 0d 00 08 07 11 04 91 6f ?? 00 00 0a 00 00 11 04 17 d6 13 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}