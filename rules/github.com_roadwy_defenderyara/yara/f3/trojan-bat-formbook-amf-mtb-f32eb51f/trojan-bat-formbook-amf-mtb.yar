rule Trojan_BAT_FormBook_AMF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 13 00 06 07 06 07 91 20 b5 03 00 00 59 d2 9c 07 17 58 0b 00 07 06 8e 69 fe 04 0d } 		$a_01_1 = {47 00 61 00 6d 00 65 00 2d 00 6f 00 66 00 2d 00 4c 00 69 00 66 00 65 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}