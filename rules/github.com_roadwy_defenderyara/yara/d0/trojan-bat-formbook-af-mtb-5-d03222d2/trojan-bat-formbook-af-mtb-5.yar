rule Trojan_BAT_FormBook_AF_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 ?? ?? ?? 0a 05 03 17 58 05 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}