rule Trojan_BAT_FormBook_AFK_MTB_16{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 0f 2b 5a 00 11 07 17 58 20 ff 00 00 00 5f 13 07 11 05 11 04 11 07 95 58 20 ff 00 00 00 5f 13 05 11 04 11 07 95 13 06 11 04 11 07 11 04 11 05 95 9e 11 04 11 05 11 06 9e 09 11 0f 07 11 0f 91 11 04 11 04 11 07 95 11 04 11 05 95 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}