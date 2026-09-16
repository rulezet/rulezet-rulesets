rule Trojan_BAT_XWorm_AXW_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.AXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 2d 06 07 9a 0c 72 ?? 00 00 70 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a de 03 26 de 00 07 17 58 } 		$a_01_1 = {61 00 31 00 30 00 34 00 34 00 32 00 31 00 36 00 2e 00 78 00 73 00 70 00 68 00 2e 00 72 00 75 00 2f 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}