rule Trojan_BAT_FormBook_NJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 6a 61 d2 9c 00 11 0d 17 6a 58 13 0d 11 0d 11 07 8e 69 17 59 } 		$a_81_1 = {74 65 6d 70 75 72 69 2e 6f 72 67 2f 44 61 74 61 53 65 74 } 	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1) >=6
 
}