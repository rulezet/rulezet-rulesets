rule Trojan_BAT_FormBook_ABO_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 06 11 07 1b 5d 1f 1f 5f 63 05 11 07 19 5d 1f 1f 5f 62 61 61 0b 00 11 21 } 		$a_03_1 = {06 19 62 0e 04 11 07 28 ?? 00 00 06 11 07 1f 11 5a 58 61 0a 11 21 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}