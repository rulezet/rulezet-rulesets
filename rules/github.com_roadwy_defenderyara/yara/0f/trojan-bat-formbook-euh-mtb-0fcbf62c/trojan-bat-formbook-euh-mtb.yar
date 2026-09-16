rule Trojan_BAT_FormBook_EUH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 08 09 11 08 09 8e 69 5d 91 03 11 08 91 61 9c 11 08 17 d6 13 08 11 08 11 07 31 e2 } 		$a_01_1 = {54 00 52 00 55 00 4d 00 50 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}