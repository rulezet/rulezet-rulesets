rule Trojan_BAT_FormBook_AFB_MTB_33{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 68 16 13 07 2b 53 07 11 06 11 07 6f ?? 00 00 0a 13 08 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 20 00 b8 00 00 2f 0d 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 20 00 b8 00 00 2f 0d 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 11 07 17 58 13 07 11 07 07 } 		$a_01_1 = {57 68 69 73 70 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}