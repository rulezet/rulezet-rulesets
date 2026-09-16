rule Trojan_BAT_FormBook_AFS_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 3f 00 16 13 04 2b 24 00 08 09 11 04 6f ?? ?? ?? 0a 13 0b 07 11 05 12 0b 28 ?? ?? ?? 0a 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 0c 11 0c 2d cc } 		$a_01_1 = {50 00 6f 00 69 00 6e 00 74 00 5f 00 4f 00 66 00 5f 00 53 00 61 00 6c 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}