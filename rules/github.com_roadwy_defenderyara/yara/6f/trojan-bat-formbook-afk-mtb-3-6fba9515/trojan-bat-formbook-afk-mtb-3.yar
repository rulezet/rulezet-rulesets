rule Trojan_BAT_FormBook_AFK_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 1f 16 5d 13 0e 06 17 58 13 0f 07 11 0f 07 8e 69 5d 91 13 10 11 0a 11 0e 91 13 11 07 06 91 11 11 61 13 12 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}