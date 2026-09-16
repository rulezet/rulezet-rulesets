rule Trojan_BAT_AsyncRat_MA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 05 00 00 04 72 43 00 00 70 7e 23 00 00 0a 6f 24 00 00 0a 28 05 00 00 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}