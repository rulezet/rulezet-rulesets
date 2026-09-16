rule Trojan_BAT_FormBook_AFO_MTB_13{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 8e 69 5d 91 13 07 08 11 05 1f 16 5d 91 13 08 07 11 05 07 11 05 91 11 08 61 11 07 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00 11 05 17 58 } 		$a_01_1 = {44 00 69 00 73 00 74 00 72 00 69 00 62 00 75 00 69 00 64 00 6f 00 72 00 61 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}