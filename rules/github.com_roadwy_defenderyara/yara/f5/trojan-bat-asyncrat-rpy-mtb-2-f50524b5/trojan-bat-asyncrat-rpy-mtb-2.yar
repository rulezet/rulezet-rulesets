rule Trojan_BAT_AsyncRat_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 28 1a 01 00 06 00 02 07 6c 02 28 0d 01 00 06 6c 5b 23 00 00 00 00 00 00 59 40 5a 28 10 01 00 06 00 07 17 d6 0b 07 06 31 d5 02 17 73 2e 01 00 06 6f 28 01 00 06 00 2a 00 00 00 13 30 01 00 07 00 00 00 07 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}