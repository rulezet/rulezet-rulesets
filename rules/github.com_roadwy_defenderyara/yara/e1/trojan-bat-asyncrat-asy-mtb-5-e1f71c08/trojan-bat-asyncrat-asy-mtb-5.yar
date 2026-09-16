rule Trojan_BAT_AsyncRat_ASY_MTB_5{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 13 00 00 01 0a 06 72 41 00 00 70 6f ?? 00 00 0a 00 72 49 00 00 70 0b 06 6f ?? 00 00 0a 74 14 00 00 01 0c 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}