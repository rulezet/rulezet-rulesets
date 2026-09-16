rule Trojan_BAT_XWorm_BAQ_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.BAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 11 10 11 10 1f 5a 61 1f 5a 61 d2 9c 09 11 10 11 10 66 66 d2 9c 11 04 11 10 11 10 1a 62 11 10 1a 63 60 d2 9c 11 10 17 58 13 10 11 10 20 00 01 00 00 fe 04 2d ca } 		$a_81_1 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}