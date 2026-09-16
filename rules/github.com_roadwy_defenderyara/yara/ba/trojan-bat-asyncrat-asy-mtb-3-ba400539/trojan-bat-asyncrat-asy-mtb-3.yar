rule Trojan_BAT_AsyncRat_ASY_MTB_3{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 1b 06 07 02 07 91 7e 02 00 00 04 07 7e 02 00 00 04 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}