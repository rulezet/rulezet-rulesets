rule Trojan_BAT_FormBook_AFM_MTB_9{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 9a 0c 08 19 8d ?? ?? ?? 01 25 16 7e 2b 00 00 04 16 9a a2 25 17 7e 2b 00 00 04 17 9a a2 25 18 } 		$a_03_1 = {16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 07 17 58 0b 07 06 8e 69 } 		$a_01_2 = {41 53 31 41 43 68 6f 77 64 68 75 72 79 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}