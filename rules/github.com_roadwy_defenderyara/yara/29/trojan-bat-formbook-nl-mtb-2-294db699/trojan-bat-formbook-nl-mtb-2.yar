rule Trojan_BAT_FormBook_NL_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 10 28 e5 00 00 06 9c 11 05 20 05 60 ec 78 5a 20 9d 8b cb 32 61 38 50 ff ff ff 11 05 20 30 f3 e6 9a 5a 20 86 d2 1d 9c 61 38 3d ff ff ff 07 13 04 11 05 20 16 14 3e b6 5a 20 a8 fc db 2d 61 38 27 ff ff ff 08 18 58 0c 11 05 20 db 8e 0a 99 5a 20 73 be cb 32 61 38 10 ff ff ff 08 06 fe 04 0d 20 9d 6c 0b a0 38 01 ff ff ff 06 18 5b 8d 62 00 00 01 0b 11 05 20 df 10 fe 24 5a 20 cd 6f d2 94 61 38 e5 fe ff ff } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}