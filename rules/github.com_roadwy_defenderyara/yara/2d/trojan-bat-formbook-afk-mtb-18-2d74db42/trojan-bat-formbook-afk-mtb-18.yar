rule Trojan_BAT_FormBook_AFK_MTB_18{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 60 16 0d 2b 4f 07 08 09 6f 55 00 00 0a 13 09 06 12 09 28 56 00 00 0a 6f 57 00 00 0a 06 6f 58 00 00 0a 20 00 b8 00 00 2f 0d 06 12 09 28 59 00 00 0a 6f 57 00 00 0a 06 6f 58 00 00 0a 20 00 b8 00 00 2f 0d 06 12 09 28 5a 00 00 0a 6f 57 00 00 0a 09 17 58 0d 09 07 6f 5b 00 00 0a 32 a8 08 17 58 0c 08 07 6f 5c 00 00 0a 32 97 07 6f } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}