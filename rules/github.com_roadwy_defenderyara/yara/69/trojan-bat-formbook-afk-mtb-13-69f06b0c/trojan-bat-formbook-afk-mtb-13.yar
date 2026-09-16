rule Trojan_BAT_FormBook_AFK_MTB_13{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 8e 69 5d 09 8e 69 58 13 10 11 10 09 8e 69 5d 13 11 09 11 11 91 13 12 11 0f 17 58 08 5d 13 13 11 13 08 58 13 14 11 14 08 5d 13 15 11 15 08 5d 08 58 } 		$a_01_1 = {4b 65 6c 6c 65 72 6d 61 6e 53 6f 66 74 77 61 72 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}