rule Trojan_BAT_Remcos_ARM_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0c 2b 21 00 11 07 11 0c 11 06 08 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 9d 00 11 0c 17 58 13 0c 11 0c 11 07 8e 69 fe 04 13 0d 11 0d 2d d1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}