rule Trojan_BAT_FormBook_ABF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 08 91 11 0a 61 13 0b 07 11 07 07 8e 69 5d 91 13 0c 11 0b 11 0c 20 00 01 00 00 58 59 13 0d 07 11 08 11 0d 20 00 01 00 00 5d d2 9c 11 06 17 58 } 		$a_01_1 = {50 00 68 00 6f 00 74 00 6f 00 53 00 6f 00 72 00 74 00 65 00 72 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}