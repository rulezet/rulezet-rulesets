rule Trojan_BAT_AsyncRat_ASY_MTB_4{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 02 8e 69 8d 15 00 00 01 0b 16 0c 16 0d 2b 17 07 09 02 09 91 06 08 91 61 d2 9c 08 17 58 06 8e 69 5d 0c 09 17 58 0d 09 02 8e 69 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}