rule Trojan_BAT_XWorm_BAN_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 ?? ?? 00 00 0a 17 73 4d 00 00 0a 13 06 11 06 09 16 09 8e 69 ?? ?? 00 00 0a 11 06 ?? ?? 00 00 0a de 10 11 07 2c 0b 11 06 2c 07 11 06 ?? ?? 00 00 0a dc 11 05 ?? ?? 00 00 0a 13 08 de 41 11 07 2c 0b 11 05 2c 07 11 05 ?? ?? 00 00 0a dc } 		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}