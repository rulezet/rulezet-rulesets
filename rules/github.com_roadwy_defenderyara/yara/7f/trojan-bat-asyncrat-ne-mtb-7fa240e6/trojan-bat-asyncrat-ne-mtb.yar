rule Trojan_BAT_AsyncRat_NE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 2c 58 1c 13 0f ?? ?? ff ff ff 08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 09 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}