rule Trojan_BAT_FormBook_BAK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 08 11 06 07 11 06 9a 1f 10 ?? ?? 00 00 0a 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d dc } 		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 73 } 		$a_01_2 = {47 65 74 54 79 70 65 } 		$a_81_3 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}