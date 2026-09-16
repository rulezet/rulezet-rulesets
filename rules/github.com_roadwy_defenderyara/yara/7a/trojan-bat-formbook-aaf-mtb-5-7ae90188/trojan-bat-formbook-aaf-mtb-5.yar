rule Trojan_BAT_FormBook_AAF_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 20 2b 25 11 1e 11 20 18 28 ?? ?? ?? 06 20 03 02 00 00 28 ?? ?? ?? 0a 13 22 11 1f 11 22 6f ?? ?? ?? 0a 11 20 18 58 13 20 11 20 11 1e } 		$a_01_1 = {47 00 61 00 73 00 74 00 72 00 6f 00 65 00 6e 00 74 00 65 00 72 00 6f 00 6c 00 6f 00 67 00 79 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}