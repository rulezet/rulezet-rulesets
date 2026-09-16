rule Trojan_BAT_XWorm_BAP_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 06 08 91 1f 30 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 9d 08 17 58 0c 08 06 8e 69 32 e0 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}