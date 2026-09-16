rule Trojan_BAT_FormBook_ABF_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 07 2b 1c 00 06 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 00 11 07 17 58 13 07 11 07 06 8e 69 fe 04 } 		$a_01_1 = {2b 18 11 06 11 09 11 05 11 09 19 5a 58 1f 18 5d 1f 0c 59 9e 11 09 17 58 13 09 11 09 11 06 8e 69 fe 04 13 0a 11 0a 2d da } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}