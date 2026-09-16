rule Trojan_BAT_XWorm_BAP_MTB_3{
	meta:
		description = "Trojan:BAT/XWorm.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 0a 00 00 0a 13 04 11 04 09 17 73 0b 00 00 0a 13 05 11 05 08 16 08 8e 69 ?? ?? 00 00 0a 11 05 ?? ?? 00 00 0a de 0c 11 05 2c 07 11 05 ?? ?? 00 00 0a dc } 		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_2 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}