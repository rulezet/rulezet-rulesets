rule Trojan_BAT_FormBook_AFK_MTB_10{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 } 		$a_01_1 = {4d 61 69 6e 53 74 6f 72 65 46 75 6e 63 74 69 6f 6e 61 6c 69 74 79 2e 4d 6f 64 65 6c 73 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}