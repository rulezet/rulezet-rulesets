rule Trojan_BAT_FormBook_AFO_MTB_11{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 31 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 } 		$a_01_1 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 41 00 72 00 69 00 74 00 68 00 6d 00 65 00 74 00 69 00 63 00 47 00 61 00 6d 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}