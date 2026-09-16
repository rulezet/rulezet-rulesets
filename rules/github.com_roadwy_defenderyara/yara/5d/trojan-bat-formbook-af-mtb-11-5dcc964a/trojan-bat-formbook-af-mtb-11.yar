rule Trojan_BAT_FormBook_AF_MTB_11{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 91 61 28 ?? ?? ?? 0a 07 09 17 58 07 8e 69 5d 91 28 } 		$a_01_1 = {54 00 65 00 73 00 74 00 46 00 69 00 72 00 73 00 74 00 57 00 46 00 61 00 70 00 70 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}