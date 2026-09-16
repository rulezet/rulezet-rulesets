rule Trojan_BAT_FormBook_NF_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 17 d6 0d 09 1f 10 31 08 1a 13 06 38 ?? ?? ?? ff 1c 2b f6 07 07 d8 20 ?? ?? ?? 00 d8 17 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 08 74 ?? ?? ?? 1b 07 28 ?? ?? ?? 06 } 		$a_01_1 = {41 00 33 00 68 00 4c 00 6f 00 51 00 } 		$a_01_2 = {57 69 6e 64 6f 77 73 41 70 70 33 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}