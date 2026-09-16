rule Trojan_BAT_FormBook_ABS_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 2d 00 11 04 72 ?? ?? ?? 70 18 19 8d ?? ?? ?? 01 25 16 09 a2 25 17 16 8c ?? ?? ?? 01 a2 25 18 11 05 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 0a 26 00 00 11 05 16 fe 02 13 07 11 07 2d ac 11 04 6f ?? ?? ?? 0a 0b 00 de 0d } 		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}