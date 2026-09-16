rule Trojan_BAT_AsyncRat_CCJN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 72 f4 6e 00 70 13 04 09 11 04 ?? fa 6e 00 70 28 ?? 00 00 0a 20 00 01 00 00 14 14 17 8d 13 00 00 01 25 16 08 a2 ?? 6b 00 00 0a 75 21 00 00 01 13 05 11 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}