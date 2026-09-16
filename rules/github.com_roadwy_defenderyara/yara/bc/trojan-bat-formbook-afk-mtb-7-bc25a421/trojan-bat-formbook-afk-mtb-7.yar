rule Trojan_BAT_FormBook_AFK_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 11 0f 11 13 95 58 20 ff 00 00 00 5f 13 2f 11 10 13 30 07 11 30 91 13 31 11 0f 11 2f 95 13 32 11 31 11 32 61 13 33 11 0e 11 30 11 33 d2 9c 11 10 17 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}