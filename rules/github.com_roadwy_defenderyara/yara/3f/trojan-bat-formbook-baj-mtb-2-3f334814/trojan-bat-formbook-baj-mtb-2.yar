rule Trojan_BAT_FormBook_BAJ_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 27 00 00 1b 0b 73 25 01 00 0a 0c 08 ?? ?? 00 00 0a 72 69 05 00 70 ?? ?? 00 00 0a ?? ?? ?? 00 0a 0d 73 27 01 00 0a 13 04 11 04 09 ?? ?? ?? 00 0a 00 11 04 18 ?? ?? ?? 00 0a 00 11 04 ?? ?? ?? 00 0a 07 16 07 8e 69 ?? ?? ?? 00 0a 13 05 02 73 1f 01 00 0a 7d be 00 00 04 02 73 1f 01 00 0a 7d bc 00 00 04 02 73 1f 01 00 0a 7d a1 00 00 04 } 		$a_81_1 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}