rule Trojan_BAT_AsyncRat_ASY_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 0f 02 7b 58 00 00 0a 08 07 08 91 9c 08 17 58 0c 08 19 32 ed de 0a 06 2c 06 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}