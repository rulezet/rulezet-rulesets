rule Trojan_BAT_FormBook_ASA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 26 00 08 11 04 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 06 09 11 06 6f ?? ?? ?? 0a 00 11 04 18 58 13 04 00 11 04 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d ca } 		$a_01_1 = {4c 00 54 00 54 00 51 00 5f 00 53 00 55 00 44 00 4f 00 4b 00 55 00 5f 00 47 00 41 00 4d 00 45 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}