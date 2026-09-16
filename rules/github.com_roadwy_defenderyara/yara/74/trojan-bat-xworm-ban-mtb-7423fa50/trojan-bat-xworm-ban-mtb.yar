rule Trojan_BAT_XWorm_BAN_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 07 11 04 91 09 11 04 09 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e1 07 73 15 00 00 0a 13 06 11 06 16 73 16 00 00 0a 13 07 73 0e 00 00 0a 13 08 11 07 11 08 } 		$a_81_1 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}