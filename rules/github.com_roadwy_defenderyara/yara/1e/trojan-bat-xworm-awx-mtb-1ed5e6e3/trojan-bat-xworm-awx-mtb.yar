rule Trojan_BAT_XWorm_AWX_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AWX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 06 8e 69 8d 16 00 00 01 0c 16 0d 2b 13 08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e7 } 		$a_01_1 = {52 00 65 00 73 00 56 00 6f 00 6c 00 6b 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}