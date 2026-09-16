rule Trojan_BAT_FormBook_AFK_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 1c 02 06 03 16 16 28 07 00 00 06 16 31 01 2a 20 e9 04 00 00 28 0d 00 00 0a 07 17 58 0b 07 1a 32 e0 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}