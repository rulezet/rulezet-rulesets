rule Trojan_BAT_FormBook_AFO_MTB_12{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 0d 02 07 11 0a 91 11 0c 61 07 11 0d 91 59 28 ?? ?? ?? 06 13 0e 07 11 0a 11 0e 28 ?? ?? ?? 0a d2 9c 00 11 0a 17 58 } 		$a_01_1 = {64 00 65 00 74 00 65 00 63 00 74 00 56 00 69 00 64 00 65 00 6f 00 41 00 70 00 70 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}