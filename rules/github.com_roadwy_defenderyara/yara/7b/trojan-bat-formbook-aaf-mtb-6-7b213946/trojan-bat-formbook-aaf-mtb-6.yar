rule Trojan_BAT_FormBook_AAF_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 8f 11 00 70 28 ?? ?? ?? 0a 0b 06 07 6f ?? ?? ?? 0a 0c 02 8e 69 8d ?? ?? ?? 01 0d 08 02 16 02 8e 69 09 16 6f ?? ?? ?? 0a 13 04 09 11 04 } 		$a_01_1 = {57 00 65 00 62 00 5f 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5f 00 5f 00 48 00 57 00 5f 00 52 00 47 00 4d 00 5f 00 32 00 30 00 31 00 32 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}