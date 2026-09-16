rule Trojan_BAT_XWorm_BAM_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 06 20 ff 00 00 00 5d 61 03 06 03 ?? ?? 00 00 0a 5d ?? ?? 00 00 0a 61 d2 9c 06 17 58 0a 06 02 8e 69 32 d8 } 		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } 		$a_81_2 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}