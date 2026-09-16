rule Trojan_BAT_FormBook_ASA_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {7b 09 00 00 04 72 59 02 00 70 6f ?? ?? ?? 0a 38 9a f8 ff ff 00 02 16 28 ?? ?? ?? 0a 38 62 05 00 00 00 02 7b 0b 00 00 04 6f ?? ?? ?? 0a 38 d7 fa ff ff 00 02 7b 12 00 00 04 6f ?? ?? ?? 0a 38 2a f4 ff ff 00 28 } 		$a_01_1 = {61 00 44 00 61 00 79 00 41 00 74 00 54 00 68 00 65 00 52 00 61 00 63 00 65 00 73 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}