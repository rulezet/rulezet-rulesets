rule Trojan_BAT_FormBook_AMF_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {5d 91 13 07 11 06 17 58 08 5d 13 08 07 11 06 91 11 07 61 13 09 07 11 08 91 13 0a 02 11 09 11 0a 28 ?? 00 00 06 13 0b 07 11 06 11 0b 28 ?? 00 00 0a 9c 00 11 06 17 58 } 		$a_01_1 = {45 00 6d 00 75 00 4c 00 69 00 73 00 74 00 65 00 72 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}