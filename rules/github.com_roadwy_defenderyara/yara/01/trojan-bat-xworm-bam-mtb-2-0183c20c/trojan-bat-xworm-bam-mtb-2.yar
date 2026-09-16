rule Trojan_BAT_XWorm_BAM_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 14 fe 01 0d 09 2d 26 00 03 ?? ?? 00 00 0a 0c 00 07 08 ?? ?? 00 00 0a 00 00 de 10 08 14 fe 01 0d 09 2d 07 08 ?? ?? 00 00 0a 00 dc 00 00 00 de 10 07 14 fe 01 0d 09 2d 07 07 ?? ?? 00 00 0a 00 dc } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}