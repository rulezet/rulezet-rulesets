rule Trojan_BAT_FormBook_AAF_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {7b 35 00 00 04 8e 69 17 59 8d 58 00 00 01 0b 02 7b 35 00 00 04 07 02 7b 35 00 00 04 8e 69 17 59 28 ?? ?? ?? 0a 11 04 16 8c 39 00 00 01 07 13 05 11 05 6f } 		$a_01_1 = {51 00 4c 00 42 00 61 00 6e 00 48 00 61 00 6e 00 67 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}