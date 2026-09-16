rule Trojan_BAT_FormBook_AFK_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 13 39 2b 2c 11 04 11 39 11 04 11 39 91 09 11 37 91 11 39 1a 5d 1d 5f 62 d2 61 11 04 11 39 17 da 91 61 20 00 01 00 00 5d b4 9c 11 39 17 d6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}