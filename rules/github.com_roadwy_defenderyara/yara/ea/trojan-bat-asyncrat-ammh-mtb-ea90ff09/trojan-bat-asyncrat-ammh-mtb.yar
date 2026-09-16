rule Trojan_BAT_AsyncRat_AMMH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 03 07 6f ?? 00 00 0a 61 d1 0d 12 03 28 ?? 00 00 0a 13 04 06 11 04 6f ?? 00 00 0a 26 07 03 6f ?? 00 00 0a 17 59 3b ?? 00 00 00 07 17 58 38 ?? 00 00 00 16 0b 08 18 58 0c 08 02 6f ?? 00 00 0a 32 b0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}