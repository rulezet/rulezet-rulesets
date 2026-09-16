rule Trojan_BAT_Heracles_BAN_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 02 73 0c 00 00 0a 0b 07 06 ?? ?? 00 00 0a 16 73 0e 00 00 0a 0c 73 0f 00 00 0a 0d 08 09 ?? ?? 00 00 0a 09 ?? ?? 00 00 0a 13 04 de 28 09 2c 06 09 ?? ?? 00 00 0a dc 08 2c 06 08 ?? ?? 00 00 0a dc } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}