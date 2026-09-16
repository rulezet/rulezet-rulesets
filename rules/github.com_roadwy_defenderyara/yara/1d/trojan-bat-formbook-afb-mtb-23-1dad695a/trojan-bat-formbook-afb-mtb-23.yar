rule Trojan_BAT_FormBook_AFB_MTB_23{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 08 91 13 0b 20 00 01 00 00 13 0c 11 0b 08 11 09 91 61 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 00 11 07 17 58 13 07 } 		$a_01_1 = {51 75 61 6e 4c 79 54 68 75 56 69 65 6e 2e 51 75 61 6e 4c 79 54 68 61 6e 68 56 69 65 6e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}