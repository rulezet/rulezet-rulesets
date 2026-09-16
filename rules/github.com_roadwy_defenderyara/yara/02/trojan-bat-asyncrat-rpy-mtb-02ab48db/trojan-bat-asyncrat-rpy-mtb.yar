rule Trojan_BAT_AsyncRat_RPY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1f 16 5d 91 13 04 07 09 91 11 04 61 13 05 09 17 58 08 5d 13 06 07 11 06 91 13 07 20 00 01 00 00 13 08 11 05 11 07 59 11 08 58 11 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}