rule Trojan_BAT_XWorm_AXW_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 0b 11 0a 11 0b 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 6f ?? 00 00 0a 26 11 04 09 11 0a 6f ?? 00 00 0a 16 6f ?? 00 00 0a 6f ?? 00 00 0a 26 00 11 0a 17 58 13 0a 11 0a 09 6f } 		$a_01_1 = {70 00 68 00 61 00 6e 00 74 00 6f 00 6d 00 2e 00 65 00 78 00 74 00 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}