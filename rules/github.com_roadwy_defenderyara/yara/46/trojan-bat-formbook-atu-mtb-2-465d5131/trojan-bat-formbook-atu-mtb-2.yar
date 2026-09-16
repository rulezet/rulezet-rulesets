rule Trojan_BAT_FormBook_ATU_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ATU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 11 07 8c 46 00 00 01 a2 28 ?? ?? ?? 0a a5 19 00 00 01 13 08 12 08 28 ?? ?? ?? 0a 13 09 07 11 09 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 08 } 		$a_01_1 = {43 00 72 00 6f 00 73 00 73 00 68 00 61 00 69 00 72 00 4e 00 65 00 74 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}