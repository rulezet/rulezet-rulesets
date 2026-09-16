rule Trojan_BAT_XWorm_BAP_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 09 06 09 91 05 09 05 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e7 } 		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_2 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}