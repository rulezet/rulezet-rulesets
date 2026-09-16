rule Trojan_BAT_FormBook_AFM_MTB_14{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 08 11 05 58 91 03 11 05 07 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 09 fe 04 13 06 11 06 2d da } 		$a_01_1 = {61 00 69 00 6e 00 76 00 65 00 73 00 74 00 69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00 } 		$a_01_2 = {55 00 42 00 4f 00 54 00 65 00 78 00 74 00 75 00 72 00 65 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}