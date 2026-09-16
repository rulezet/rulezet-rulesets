rule Trojan_BAT_FormBook_NI_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 91 11 07 61 13 09 07 11 08 91 13 0a 02 } 		$a_01_1 = {13 06 11 06 11 05 1f 16 5d 91 13 07 11 05 17 58 08 5d 13 08 } 		$a_81_2 = {2f 44 61 74 61 53 65 74 41 2e 78 73 64 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_81_2  & 1)*1) >=11
 
}