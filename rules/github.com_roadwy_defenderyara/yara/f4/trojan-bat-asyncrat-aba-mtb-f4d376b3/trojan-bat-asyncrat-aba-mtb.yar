rule Trojan_BAT_AsyncRat_ABA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 03 08 18 5a 18 6f ?? 00 00 0a 0d 06 08 09 1f 10 28 ?? 00 00 0a 9c 06 08 8f ?? 00 00 01 25 47 07 61 d2 52 00 08 17 58 0c 08 06 8e 69 fe 04 13 04 11 04 2d cb } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}