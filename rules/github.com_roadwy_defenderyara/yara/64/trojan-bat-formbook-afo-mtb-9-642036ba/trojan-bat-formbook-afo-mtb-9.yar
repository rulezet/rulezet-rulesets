rule Trojan_BAT_FormBook_AFO_MTB_9{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 91 13 05 08 17 8d ?? ?? ?? 01 25 16 11 05 9c 6f ?? ?? ?? 0a 09 18 58 0d 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d c4 } 		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 48 00 61 00 6e 00 67 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}