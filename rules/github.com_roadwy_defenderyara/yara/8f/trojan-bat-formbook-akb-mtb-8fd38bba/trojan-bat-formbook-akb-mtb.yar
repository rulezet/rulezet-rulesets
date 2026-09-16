rule Trojan_BAT_FormBook_AKB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 06 11 07 1b 5d 1f 1f 5f 63 05 11 07 19 5d 1f 1f 5f 62 61 61 0b 11 21 } 		$a_01_1 = {07 06 61 1f 18 5f 1f 10 fe 01 2b 01 16 13 09 11 09 2d 08 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}