rule Trojan_BAT_FormBook_AFK_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 5a 58 11 11 07 6f ?? 00 00 0a 5a 58 13 0a 11 0c 11 05 11 0a 91 58 13 0c 11 0d 11 05 11 0a 17 58 91 58 13 0d 11 0e 11 05 11 0a 18 58 91 58 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}