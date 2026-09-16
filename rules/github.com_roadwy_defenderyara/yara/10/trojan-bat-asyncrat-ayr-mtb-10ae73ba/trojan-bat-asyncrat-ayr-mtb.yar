rule Trojan_BAT_AsyncRat_AYR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 04 09 6f 26 00 00 0a 13 05 06 12 05 28 27 00 00 0a 6f 28 00 00 0a 26 00 11 04 17 58 13 04 11 04 07 fe 02 16 fe 01 13 06 11 06 2d d1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}